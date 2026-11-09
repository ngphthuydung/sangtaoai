"""Scam analysis endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.schemas.scam_analysis import ScamAnalysisRequest, ScamAnalysisResponse
from app.services.scam_analysis import (
    AudioAnalysisUnavailable,
    ImageAnalysisUnavailable,
    ScamAnalysisService,
)

router = APIRouter(tags=["Phân tích lừa đảo"])
analysis_service = ScamAnalysisService()
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024
IMAGE_SIGNATURES = {
    "image/jpeg": lambda image: image.startswith(b"\xff\xd8\xff"),
    "image/png": lambda image: image.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/webp": lambda image: (
        len(image) >= 12 and image.startswith(b"RIFF") and image[8:12] == b"WEBP"
    ),
}
MAX_AUDIO_SIZE_BYTES = 20 * 1024 * 1024
AUDIO_MIME_TYPES = {
    "audio/mpeg": "audio/mpeg",
    "audio/wav": "audio/wav",
    "audio/x-wav": "audio/wav",
    "audio/mp4": "audio/mp4",
}


def has_audio_signature(audio: bytes, mime_type: str) -> bool:
    if mime_type == "audio/mpeg":
        return audio.startswith(b"ID3") or (
            len(audio) >= 2 and audio[0] == 0xFF and audio[1] & 0xE0 == 0xE0
        )
    if mime_type == "audio/wav":
        return len(audio) >= 12 and audio.startswith(b"RIFF") and audio[8:12] == b"WAVE"
    if mime_type == "audio/mp4":
        return (
            len(audio) >= 12
            and audio[4:8] == b"ftyp"
            and audio[8:12] in {b"M4A ", b"M4B ", b"M4P "}
        )
    return False


def get_scam_analysis_service() -> ScamAnalysisService:
    return analysis_service


@router.post(
    "/scam-analysis",
    response_model=ScamAnalysisResponse,
    summary="Phân tích nội dung có dấu hiệu lừa đảo",
)
async def analyze_scam(
    request: ScamAnalysisRequest,
    service: ScamAnalysisService = Depends(get_scam_analysis_service),
) -> ScamAnalysisResponse:
    """Analyze submitted content only when the caller explicitly consents."""
    return await service.analyze(request)


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
        raise HTTPException(
            status_code=403,
            detail="Cần đồng ý gửi ảnh đến Gemini để phân tích.",
        )

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in IMAGE_SIGNATURES:
        raise HTTPException(
            status_code=415,
            detail="Chỉ hỗ trợ ảnh JPG, PNG hoặc WEBP.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_IMAGE_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="Ảnh vượt quá giới hạn 10 MB.")
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Kích thước ảnh không hợp lệ.") from error

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_IMAGE_SIZE_BYTES:
            raise HTTPException(status_code=413, detail="Ảnh vượt quá giới hạn 10 MB.")
        chunks.append(chunk)

    image = b"".join(chunks)
    if not image:
        raise HTTPException(status_code=400, detail="Vui lòng chọn một ảnh hợp lệ.")
    if not IMAGE_SIGNATURES[content_type](image):
        raise HTTPException(
            status_code=415,
            detail="Nội dung ảnh không khớp với định dạng tệp đã gửi.",
        )

    try:
        return await service.analyze_image(image, content_type)
    except ImageAnalysisUnavailable as error:
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
        raise HTTPException(
            status_code=403,
            detail="Cần đồng ý gửi âm thanh đến Google Gemini để phân tích.",
        )

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    mime_type = AUDIO_MIME_TYPES.get(content_type)
    if mime_type is None:
        raise HTTPException(
            status_code=415,
            detail="Chỉ hỗ trợ tệp âm thanh MP3, WAV hoặc M4A.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_AUDIO_SIZE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Âm thanh vượt quá giới hạn 20 MB.",
                )
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail="Kích thước tệp âm thanh không hợp lệ.",
            ) from error

    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_AUDIO_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Âm thanh vượt quá giới hạn 20 MB.",
            )
        chunks.append(chunk)

    audio = b"".join(chunks)
    if not audio:
        raise HTTPException(status_code=400, detail="Vui lòng chọn một tệp âm thanh.")
    if not has_audio_signature(audio, mime_type):
        raise HTTPException(
            status_code=415,
            detail="Nội dung tệp không khớp với định dạng MP3, WAV hoặc M4A đã gửi.",
        )

    try:
        return await service.analyze_audio(audio, mime_type)
    except AudioAnalysisUnavailable as error:
        raise HTTPException(status_code=503, detail=str(error)) from error
