"""API tests for scam analysis with an injected, non-network provider."""

from io import BytesIO
import wave

from PIL import Image
import pytest
from fastapi.testclient import TestClient

from app.api.v1.scam_analysis import get_scam_analysis_service
from app.core.config import Settings
from app.main import app
from app.schemas.scam_analysis import (
    AnalysisFailureReason,
    AnalysisStatus,
    AudioModelAnalysisOutput,
    ImageModelAnalysisOutput,
    ModelAnalysisOutput,
    RiskLevel,
)
from app.services.ai_providers import AIProviderError
from app.services.media_validation import validate_image
from app.services.scam_analysis import ScamAnalysisService

MP3_FIXTURE = b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb\x90\x64audio"


def image_fixture(image_format: str) -> bytes:
    output = BytesIO()
    Image.new("RGB", (4, 3), color=(20, 40, 60)).save(output, format=image_format)
    return output.getvalue()


def wav_fixture() -> bytes:
    output = BytesIO()
    with wave.open(output, "wb") as target:
        target.setnchannels(1)
        target.setsampwidth(2)
        target.setframerate(16000)
        target.writeframes(b"\x00\x00" * 160)
    return output.getvalue()


class MockGeminiProvider:
    name = "gemini"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def analyze(self, content: str, context: str | None) -> ModelAnalysisOutput:
        self.calls.append((content, context))
        return ModelAnalysisOutput(
            risk_level=RiskLevel.HIGH_RISK,
            summary="Có dấu hiệu yêu cầu thông tin nhạy cảm.",
            detected_behaviors=[
                {
                    "type": "CREDENTIAL_OTP_THEFT",
                    "name_vi": "Lừa lấy mã OTP",
                    "description": "Yêu cầu mã xác thực.",
                    "evidence": "Gửi mã OTP cho tôi",
                    "explanation": "Mã OTP là thông tin bí mật.",
                }
            ],
            recommendations=["Không cung cấp OTP."],
        )


class MockImageGeminiProvider:
    name = "gemini"

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, str]] = []

    async def analyze_image(self, image: bytes, mime_type: str) -> ImageModelAnalysisOutput:
        self.calls.append((image, mime_type))
        return ImageModelAnalysisOutput(
            risk_level=RiskLevel.HIGH_RISK,
            summary="Ảnh yêu cầu cung cấp mã OTP.",
            visible_text="Gửi mã OTP cho tôi",
            detected_behaviors=[
                {
                    "type": "CREDENTIAL_OTP_THEFT",
                    "name_vi": "Lừa lấy mã OTP",
                    "description": "Yêu cầu mã xác thực.",
                    "evidence": "Gửi mã OTP cho tôi",
                    "explanation": "Mã OTP là thông tin bí mật.",
                }
            ],
            recommendations=["Không cung cấp OTP."],
        )


class MockAudioGeminiProvider:
    name = "gemini"

    def __init__(self) -> None:
        self.calls: list[tuple[bytes, str]] = []

    async def analyze_audio(self, audio: bytes, mime_type: str) -> AudioModelAnalysisOutput:
        self.calls.append((audio, mime_type))
        return AudioModelAnalysisOutput(
            risk_level=RiskLevel.HIGH_RISK,
            summary="Người gọi yêu cầu mã OTP.",
            transcript="Gửi mã OTP cho tôi, số điện thoại 0912345678.",
            detected_behaviors=[
                {
                    "type": "CREDENTIAL_OTP_THEFT",
                    "name_vi": "Lừa lấy mã OTP",
                    "description": "Yêu cầu mã xác thực.",
                    "evidence": "Gửi mã OTP cho tôi",
                    "explanation": "Không gọi lại số 0912345678.",
                }
            ],
            recommendations=["Không cung cấp OTP."],
        )


def audio_service(provider: MockAudioGeminiProvider) -> ScamAnalysisService:
    return ScamAnalysisService(audio_provider=provider)


def install_analysis_service(monkeypatch, service: ScamAnalysisService) -> None:
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )


@pytest.mark.parametrize(
    ("mime_type", "audio"),
    [
        ("audio/mpeg", MP3_FIXTURE),
        ("audio/wav", wav_fixture()),
        ("audio/mp4", b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00"),
    ],
)
def test_audio_endpoint_returns_mocked_analysis_without_transcript(
    monkeypatch, mime_type, audio
):
    provider = MockAudioGeminiProvider()
    install_analysis_service(monkeypatch, audio_service(provider))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=audio,
            headers={"content-type": mime_type},
        )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "HIGH_RISK"
    assert response.json()["detected_behaviors"][0]["evidence"] == "Gửi mã OTP cho tôi"
    assert provider.calls == [(audio, mime_type)]
    assert "transcript" not in response.json()
    assert "0912345678" not in response.text


def test_audio_endpoint_requires_consent_before_provider_call(monkeypatch):
    provider = MockAudioGeminiProvider()
    install_analysis_service(monkeypatch, audio_service(provider))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio",
            content=MP3_FIXTURE,
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 403
    assert provider.calls == []


def test_audio_endpoint_rejects_unsupported_or_mismatched_audio(monkeypatch):
    provider = MockAudioGeminiProvider()
    install_analysis_service(monkeypatch, audio_service(provider))

    with TestClient(app) as client:
        unsupported = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=b"GIF89a",
            headers={"content-type": "audio/gif"},
        )
        mismatch = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=b"not an mp3",
            headers={"content-type": "audio/mpeg"},
        )

    assert unsupported.status_code == 415
    assert mismatch.status_code == 415
    assert provider.calls == []


def test_audio_endpoint_rejects_oversized_body_before_analysis(monkeypatch):
    from app.api.v1.scam_analysis import MAX_AUDIO_SIZE_BYTES

    provider = MockAudioGeminiProvider()
    install_analysis_service(monkeypatch, audio_service(provider))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=MP3_FIXTURE,
            headers={
                "content-type": "audio/mpeg",
                "content-length": str(MAX_AUDIO_SIZE_BYTES + 1),
            },
        )

    assert response.status_code == 413
    assert provider.calls == []


def test_audio_endpoint_reports_gemini_unavailable_without_fake_result(monkeypatch):
    install_analysis_service(
        monkeypatch,
        ScamAnalysisService(configuration=Settings(AI_ENABLED=False)),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=MP3_FIXTURE,
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Không thể phân tích do dịch vụ AI gặp sự cố."


def test_audio_endpoint_reports_provider_failure_without_logging_audio(
    monkeypatch, caplog
):
    class FailingAudioProvider:
        name = "gemini"

        async def analyze_audio(
            self, audio: bytes, mime_type: str
        ) -> AudioModelAnalysisOutput:
            raise AIProviderError(
                "Không xử lý được bản ghi 0912345678",
                status_code=401,
            )

    install_analysis_service(
        monkeypatch,
        ScamAnalysisService(audio_provider=FailingAudioProvider()),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=MP3_FIXTURE,
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Không thể phân tích do dịch vụ AI gặp sự cố."
    assert "0912345678" not in caplog.text


def test_audio_endpoint_rejects_id3_without_audio_frames(monkeypatch):
    provider = MockAudioGeminiProvider()
    install_analysis_service(monkeypatch, audio_service(provider))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=b"ID3\x04\x00\x00\x00\x00\x00\x00no-frames",
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 415
    assert response.json()["detail"].startswith("Tệp âm thanh bị lỗi")
    assert provider.calls == []


def test_media_failure_returns_safe_request_diagnostics(monkeypatch, caplog):
    install_analysis_service(
        monkeypatch,
        ScamAnalysisService(configuration=Settings(AI_ENABLED=False)),
    )
    private_marker = "PRIVATE_MEDIA_CONTENT"

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/audio?allow_external_processing=true",
            content=MP3_FIXTURE + private_marker.encode(),
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 503
    assert response.headers["x-request-id"]
    assert response.headers["x-processing-stage"] == "provider_analysis"
    assert response.headers["x-error-category"] == "provider_unavailable"
    assert response.headers["x-processing-duration-ms"].isdigit()
    assert response.headers["x-ai-retry-count"] == "0"
    assert private_marker not in caplog.text


def test_transient_retry_count_is_exposed_in_request_diagnostics(monkeypatch):
    class RetryOnceProvider:
        name = "gemini"

        def __init__(self):
            self.calls = 0

        async def analyze(self, content: str, context: str | None) -> ModelAnalysisOutput:
            self.calls += 1
            if self.calls == 1:
                raise AIProviderError(
                    "temporary upstream failure",
                    status_code=503,
                    failure_reason=AnalysisFailureReason.HTTP_ERROR,
                    retryable=True,
                )
            return await MockGeminiProvider().analyze(content, context)

    provider = RetryOnceProvider()
    install_analysis_service(
        monkeypatch,
        ScamAnalysisService(gemini_provider=provider),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={
                "content": "Gửi mã OTP cho tôi",
                "allow_external_processing": True,
            },
        )

    assert response.status_code == 200
    assert response.headers["x-request-id"]
    assert response.headers["x-processing-stage"] == "provider_analysis"
    assert response.headers["x-ai-retry-count"] == "1"
    assert provider.calls == 2


def test_scam_analysis_endpoint_requires_consent_before_provider_call(monkeypatch):
    provider = MockGeminiProvider()
    service = ScamAnalysisService(
        gemini_provider=provider,
        configuration=Settings(AI_ENABLED=True, OPENAI_API_KEY=None),
    )
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={"content": "Gửi mã OTP cho tôi"},
        )

    assert response.status_code == 200
    assert response.json()["analysis_method"] == "EXTERNAL_ANALYSIS_NOT_CONSENTED"
    assert provider.calls == []


def test_scam_analysis_endpoint_returns_mocked_gemini_result(monkeypatch):
    provider = MockGeminiProvider()
    service = ScamAnalysisService(
        gemini_provider=provider,
        configuration=Settings(AI_ENABLED=True, OPENAI_API_KEY=None),
    )
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={
                "content": "Gửi mã OTP cho tôi",
                "context": "Tin nhắn từ người lạ",
                "allow_external_processing": True,
            },
        )

    assert response.status_code == 200
    assert response.json()["analysis_method"] == "GEMINI_CONTEXTUAL_ANALYSIS"
    assert response.json()["risk_level"] == "HIGH_RISK"
    assert response.json()["analysis_status"] == "COMPLETED"
    assert len(provider.calls) == 1
    assert provider.calls[0] == ("Gửi mã OTP cho tôi", "Tin nhắn từ người lạ")


def test_scam_analysis_endpoint_rejects_oversized_content():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={"content": "x" * 12001},
        )

    assert response.status_code == 422


@pytest.mark.parametrize(
    ("failure_reason", "provider_error"),
    [
        (AnalysisFailureReason.AI_UNAVAILABLE, "unavailable"),
        (AnalysisFailureReason.INVALID_RESPONSE, "invalid response"),
        (AnalysisFailureReason.TIMEOUT, "timed out"),
        (AnalysisFailureReason.HTTP_ERROR, "HTTP error"),
    ],
)
def test_scam_analysis_endpoint_reports_ai_failure_separately_from_insufficient_evidence(
    monkeypatch, failure_reason, provider_error
):
    class FailingProvider:
        name = "gemini"

        async def analyze(self, content: str, context: str | None) -> ModelAnalysisOutput:
            raise AIProviderError(
                provider_error,
                status_code=502 if failure_reason == AnalysisFailureReason.HTTP_ERROR else None,
                failure_reason=failure_reason,
            )

    service = ScamAnalysisService(
        gemini_provider=FailingProvider(),
        configuration=Settings(AI_ENABLED=True, OPENAI_API_KEY=None),
    )
    install_analysis_service(monkeypatch, service)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={
                "content": (
                    "Ngân hàng ABC yêu cầu mật khẩu và mã OTP để xác minh tài khoản."
                ),
                "allow_external_processing": True,
            },
        )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_level"] == "INSUFFICIENT_DATA"
    assert result["analysis_status"] == AnalysisStatus.FAILED.value
    assert result["analysis_failure_reason"] == failure_reason.value
    assert result["summary"] == "Không thể phân tích do dịch vụ AI gặp sự cố."


def test_image_endpoint_requires_explicit_consent(monkeypatch):
    provider = MockImageGeminiProvider()
    service = ScamAnalysisService(image_provider=provider)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/image",
            content=b"\x89PNG\r\n\x1a\nimage",
            headers={"content-type": "image/png"},
        )

    assert response.status_code == 403
    assert provider.calls == []


def test_image_endpoint_validates_type_and_signature(monkeypatch):
    provider = MockImageGeminiProvider()
    service = ScamAnalysisService(image_provider=provider)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        unsupported = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=b"not an image",
            headers={"content-type": "image/gif"},
        )
        mismatch = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=b"\x89PNG\r\n\x1a\nimage",
            headers={"content-type": "image/jpeg"},
        )

    assert unsupported.status_code == 415
    assert mismatch.status_code == 415
    assert provider.calls == []


def test_image_endpoint_rejects_oversized_body_before_analysis(monkeypatch):
    provider = MockImageGeminiProvider()
    service = ScamAnalysisService(image_provider=provider)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=b"\x89PNG\r\n\x1a\n",
            headers={
                "content-type": "image/png",
                "content-length": str(10 * 1024 * 1024 + 1),
            },
        )

    assert response.status_code == 413
    assert provider.calls == []


def test_image_endpoint_rejects_truncated_image_even_with_valid_signature(monkeypatch):
    provider = MockImageGeminiProvider()
    install_analysis_service(monkeypatch, ScamAnalysisService(image_provider=provider))

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=b"\xff\xd8\xff" + b"not-a-complete-jpeg",
            headers={"content-type": "image/jpeg"},
        )

    assert response.status_code == 415
    assert "Ảnh bị lỗi" in response.json()["detail"]
    assert provider.calls == []


def test_image_validation_decodes_image_and_returns_dimensions():
    image = image_fixture("PNG")

    assert validate_image(image, "image/png") == (4, 3)
    with pytest.raises(ValueError):
        validate_image(image, "image/jpeg")


@pytest.mark.parametrize(
    ("mime_type", "image"),
    [
        ("image/jpeg", image_fixture("JPEG")),
        ("image/png", image_fixture("PNG")),
        ("image/webp", image_fixture("WEBP")),
    ],
)
def test_image_endpoint_returns_gemini_analysis(monkeypatch, mime_type, image):
    provider = MockImageGeminiProvider()
    service = ScamAnalysisService(image_provider=provider)
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=image,
            headers={"content-type": mime_type},
        )

    assert response.status_code == 200
    assert response.json()["risk_level"] == "HIGH_RISK"
    assert response.json()["analysis_method"] == "GEMINI_CONTEXTUAL_ANALYSIS"
    assert response.json()["detected_behaviors"][0]["evidence"] == "Gửi mã OTP cho tôi"
    assert provider.calls == [(image, mime_type)]


def test_image_endpoint_reports_gemini_unavailable_without_fake_result(monkeypatch):
    service = ScamAnalysisService(configuration=Settings(AI_ENABLED=False))
    monkeypatch.setitem(
        app.dependency_overrides,
        get_scam_analysis_service,
        lambda: service,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis/image?allow_external_processing=true",
            content=image_fixture("PNG"),
            headers={"content-type": "image/png"},
        )

    assert response.status_code == 503
    assert response.json()["detail"] == "Không thể phân tích do dịch vụ AI gặp sự cố."
