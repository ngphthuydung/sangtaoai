"""Scam analysis endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.core.request_diagnostics import RequestDiagnostics
from app.schemas.scam_analysis import ScamAnalysisRequest, ScamAnalysisResponse
from app.services.scam_analysis import (
    AudioAnalysisUnavailable,
    ImageAnalysisUnavailable,
    ScamAnalysisService,
)
from app.services.media_validation import (
    InvalidMediaError,
    has_audio_signature,
    validate_image,
)

router = APIRouter(tags=["Phân tích lừa đảo"])
analysis_service = ScamAnalysisService()
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024
MAX_AUDIO_SIZE_BYTES = 20 * 1024 * 1024
AUDIO_MIME_TYPES = {
    "audio/mpeg": "audio/mpeg",
    "audio/wav": "audio/wav",
    "audio/x-wav": "audio/wav",
    "audio/mp4": "audio/mp4",
}


def set_request_stage(request: Request, stage: str) -> None:
    diagnostics: RequestDiagnostics = request.state.diagnostics
    diagnostics.stage = stage


def set_request_failure(
    request: Request,
    category: str,
    status_code: int,
) -> None:
    diagnostics: RequestDiagnostics = request.state.diagnostics
    diagnostics.error_category = category
    diagnostics.http_status = status_code


def set_request_status(request: Request, status_code: int, category: str) -> None:
    diagnostics: RequestDiagnostics = request.state.diagnostics
    diagnostics.http_status = status_code
    if diagnostics.error_category == "none":
        diagnostics.error_category = category


def get_scam_analysis_service() -> ScamAnalysisService:
    return analysis_service


@router.post(
    "/scam-analysis",
    response_model=ScamAnalysisResponse,
    summary="Phân tích nội dung có dấu hiệu lừa đảo",
)
async def analyze_scam(
    http_request: Request,
    analysis_request: ScamAnalysisRequest,
    service: ScamAnalysisService = Depends(get_scam_analysis_service),
) -> ScamAnalysisResponse:
    """Analyze submitted content only when the caller explicitly consents."""
    set_request_stage(
        http_request,
        "provider_analysis"
        if analysis_request.allow_external_processing
        else "consent",
    )
    return await service.analyze(analysis_request)


@router.post(
    "/scam-analysis/image",
    response_model=ScamAnalysisResponse,
    summary="Phân tích hình ảnh có dấu hiệu lừa đảo bằng Gemini",
)
async def analyze_scam_image(
    request: Request,
    allow_external_processing: bool = Query(default=False),
    service: ScamAnalysisService = Depends(get_scam_analysis_service),
) -> ScamAnalysisResponse:
    """Stream and validate one image before sending it to Gemini Vision."""
    if not allow_external_processing:
        set_request_stage(request, "consent")
        set_request_failure(request, "consent_required", 403)
        raise HTTPException(
            status_code=403,
            detail="Cần đồng ý gửi ảnh đến Gemini để phân tích.",
        )

    set_request_stage(request, "validate_headers")
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"image/jpeg", "image/png", "image/webp"}:
        set_request_failure(request, "unsupported_media_type", 415)
        raise HTTPException(
            status_code=415,
            detail="Chỉ hỗ trợ ảnh JPG, PNG hoặc WEBP.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_IMAGE_SIZE_BYTES:
                set_request_failure(request, "payload_too_large", 413)
                raise HTTPException(status_code=413, detail="Ảnh vượt quá giới hạn 10 MB.")
        except ValueError as error:
            set_request_failure(request, "invalid_content_length", 400)
            raise HTTPException(status_code=400, detail="Kích thước ảnh không hợp lệ.") from error

    set_request_stage(request, "receive")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_IMAGE_SIZE_BYTES:
            set_request_failure(request, "payload_too_large", 413)
            raise HTTPException(status_code=413, detail="Ảnh vượt quá giới hạn 10 MB.")
        chunks.append(chunk)

    image = b"".join(chunks)
    if not image:
        set_request_failure(request, "empty_upload", 400)
        raise HTTPException(status_code=400, detail="Vui lòng chọn một ảnh hợp lệ.")
    set_request_stage(request, "validate_media")
    try:
        validate_image(image, content_type)
    except InvalidMediaError as error:
        set_request_failure(request, "invalid_image", 415)
        raise HTTPException(
            status_code=415,
            detail=(
                "Ảnh bị lỗi, không đúng định dạng đã chọn hoặc vượt giới hạn "
                "20 megapixel. Hãy lưu lại ảnh dưới dạng JPG, PNG hoặc WEBP."
            ),
        ) from error

    set_request_stage(request, "provider_analysis")
    try:
        return await service.analyze_image(image, content_type)
    except ImageAnalysisUnavailable as error:
        set_request_status(request, 503, "provider_unavailable")
        raise HTTPException(status_code=503, detail=str(error)) from error


@router.post(
    "/scam-analysis/audio",
    response_model=ScamAnalysisResponse,
    summary="Phiên âm và phân tích âm thanh bằng Gemini",
)
async def analyze_scam_audio(
    request: Request,
    allow_external_processing: bool = Query(default=False),
    service: ScamAnalysisService = Depends(get_scam_analysis_service),
) -> ScamAnalysisResponse:
    """Validate an in-memory audio stream and send it to Gemini only with consent."""
    if not allow_external_processing:
        set_request_stage(request, "consent")
        set_request_failure(request, "consent_required", 403)
        raise HTTPException(
            status_code=403,
            detail="Cần đồng ý gửi âm thanh đến Google Gemini để phân tích.",
        )

    set_request_stage(request, "validate_headers")
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    mime_type = AUDIO_MIME_TYPES.get(content_type)
    if mime_type is None:
        set_request_failure(request, "unsupported_media_type", 415)
        raise HTTPException(
            status_code=415,
            detail="Chỉ hỗ trợ tệp âm thanh MP3, WAV hoặc M4A.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_AUDIO_SIZE_BYTES:
                set_request_failure(request, "payload_too_large", 413)
                raise HTTPException(
                    status_code=413,
                    detail="Âm thanh vượt quá giới hạn 20 MiB.",
                )
        except ValueError as error:
            set_request_failure(request, "invalid_content_length", 400)
            raise HTTPException(
                status_code=400,
                detail="Kích thước tệp âm thanh không hợp lệ.",
            ) from error

    set_request_stage(request, "receive")
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_AUDIO_SIZE_BYTES:
            set_request_failure(request, "payload_too_large", 413)
            raise HTTPException(
                status_code=413,
                detail="Âm thanh vượt quá giới hạn 20 MiB.",
            )
        chunks.append(chunk)

    audio = b"".join(chunks)
    if not audio:
        set_request_failure(request, "empty_upload", 400)
        raise HTTPException(status_code=400, detail="Vui lòng chọn một tệp âm thanh.")
    if not has_audio_signature(audio, mime_type):
        set_request_failure(request, "invalid_audio", 415)
        raise HTTPException(
            status_code=415,
            detail=(
                "Tệp âm thanh bị lỗi hoặc không đúng định dạng đã chọn. "
                "Hãy xuất lại thành MP3, WAV PCM hoặc M4A."
            ),
        )

    set_request_stage(request, "provider_analysis")
    try:
        return await service.analyze_audio(audio, mime_type)
    except AudioAnalysisUnavailable as error:
        set_request_status(request, 503, "provider_unavailable")
        raise HTTPException(status_code=503, detail=str(error)) from error
