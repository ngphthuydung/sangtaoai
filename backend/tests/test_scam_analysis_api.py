"""API tests for scam analysis with an injected, non-network provider."""

import pytest
from fastapi.testclient import TestClient

from app.api.v1.scam_analysis import get_scam_analysis_service
from app.core.config import Settings
from app.main import app
from app.schemas.scam_analysis import (
    AudioModelAnalysisOutput,
    ImageModelAnalysisOutput,
    ModelAnalysisOutput,
    RiskLevel,
)
from app.services.ai_providers import AIProviderError
from app.services.scam_analysis import ScamAnalysisService


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
        ("audio/mpeg", b"ID3mock-mp3"),
        ("audio/wav", b"RIFF\x04\x00\x00\x00WAVEmock"),
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
            content=b"ID3mock-mp3",
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
            content=b"ID3",
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
            content=b"ID3mock-mp3",
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 503
    assert "Gemini chưa được bật" in response.json()["detail"]


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
            content=b"ID3mock-mp3",
            headers={"content-type": "audio/mpeg"},
        )

    assert response.status_code == 503
    assert "Gemini hiện không khả dụng" in response.json()["detail"]
    assert "HTTP 401" in response.json()["detail"]
    assert "0912345678" not in caplog.text
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
    assert len(provider.calls) == 1
    assert provider.calls[0] == ("Gửi mã OTP cho tôi", "Tin nhắn từ người lạ")


def test_scam_analysis_endpoint_rejects_oversized_content():
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/scam-analysis",
            json={"content": "x" * 12001},
        )

    assert response.status_code == 422


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


@pytest.mark.parametrize(
    ("mime_type", "image"),
    [
        ("image/jpeg", b"\xff\xd8\xff\xdbJPEG"),
        ("image/png", b"\x89PNG\r\n\x1a\nPNG"),
        ("image/webp", b"RIFF\x04\x00\x00\x00WEBP"),
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
            content=b"\x89PNG\r\n\x1a\nimage",
            headers={"content-type": "image/png"},
        )

    assert response.status_code == 503
    assert "Gemini chưa được bật" in response.json()["detail"]
