"""Hybrid AI orchestration for contextual scam analysis."""

import asyncio
import logging
import re

from pydantic import ValidationError

from app.core.config import Settings, settings
from app.schemas.scam_analysis import (
    AnalysisMethod,
    AudioModelAnalysisOutput,
    CrossCheckStatus,
    DetectedBehavior,
    ImageModelAnalysisOutput,
    ModelAnalysisOutput,
    RiskLevel,
    ScamAnalysisRequest,
    ScamAnalysisResponse,
)
from app.services.ai_providers import (
    AIAnalysisProvider,
    AIAudioAnalysisProvider,
    AIImageAnalysisProvider,
    AIProviderError,
    GeminiProvider,
    OpenAIProvider,
)
from app.services.evidence_engine import EvidenceAssessment, EvidenceEngine

logger = logging.getLogger(__name__)


class ImageAnalysisUnavailable(Exception):
    """Raised when Gemini cannot provide an image analysis."""


class AudioAnalysisUnavailable(Exception):
    """Raised when Gemini cannot provide an audio analysis."""


class ScamAnalysisService:
    """Prefer Gemini and use OpenAI only as an optional fallback."""

    def __init__(
        self,
        openai_provider: AIAnalysisProvider | None = None,
        gemini_provider: AIAnalysisProvider | None = None,
        configuration: Settings = settings,
        evidence_engine: EvidenceEngine | None = None,
        image_provider: AIImageAnalysisProvider | None = None,
        audio_provider: AIAudioAnalysisProvider | None = None,
    ) -> None:
        self.openai_provider = openai_provider
        self.gemini_provider = gemini_provider
        self.image_provider = image_provider
        self.audio_provider = audio_provider
        self.configuration = configuration
        self.evidence_engine = evidence_engine or EvidenceEngine()
        self._semaphore = asyncio.Semaphore(configuration.AI_MAX_CONCURRENT_REQUESTS)

    async def analyze(self, request: ScamAnalysisRequest) -> ScamAnalysisResponse:
        if not request.allow_external_processing:
            return self._unavailable(AnalysisMethod.EXTERNAL_ANALYSIS_NOT_CONSENTED)

        full_input = request.content + ("\n" + request.context if request.context else "")
        if len(full_input) > self.configuration.AI_MAX_INPUT_CHARS:
            return self._unavailable(AnalysisMethod.INPUT_LIMIT_EXCEEDED)

        primary_provider = self.gemini_provider or self._configured_gemini()
        if primary_provider is None:
            primary_provider = self.openai_provider or self._configured_openai()
        if primary_provider is None:
            return self._unavailable(AnalysisMethod.LLM_NOT_CONFIGURED)

        safe_content = redact_sensitive_data(request.content)
        safe_context = redact_sensitive_data(request.context) if request.context else None
        evidence_source = safe_content + ("\n" + safe_context if safe_context else "")

        async with self._semaphore:
            try:
                primary = await asyncio.wait_for(
                    primary_provider.analyze(safe_content, safe_context),
                    timeout=self.configuration.AI_TIMEOUT_SECONDS,
                )
            except (
                AIProviderError,
                TimeoutError,
                ValueError,
                KeyError,
                IndexError,
                TypeError,
                ValidationError,
            ) as error:
                logger.warning(
                    "%s analysis failed (provider_status=%s, error=%s)",
                    primary_provider.name,
                    error.status_code if isinstance(error, AIProviderError) else None,
                    type(error).__name__,
                )
                return self._unavailable(AnalysisMethod.LLM_UNAVAILABLE)

            primary_assessment = self.evidence_engine.assess(
                primary,
                primary_provider.name,
                evidence_source,
            )
            primary_invalid = self._has_unusable_high_risk_evidence(
                primary, primary_assessment
            )
            return self._primary_result(
                primary,
                primary_assessment,
                primary_invalid,
                CrossCheckStatus.NOT_REQUESTED,
                "Mỗi yêu cầu chỉ sử dụng một nhà cung cấp AI.",
                self._single_provider_method(primary_provider),
            )

    async def analyze_image(
        self, image: bytes, mime_type: str
    ) -> ScamAnalysisResponse:
        provider = self.image_provider or self._configured_gemini()
        if provider is None:
            raise ImageAnalysisUnavailable(
                "Gemini chưa được bật hoặc chưa cấu hình API key; ảnh chưa được phân tích."
            )

        try:
            async with self._semaphore:
                output: ImageModelAnalysisOutput = await asyncio.wait_for(
                    provider.analyze_image(image, mime_type),
                    timeout=self.configuration.AI_TIMEOUT_SECONDS,
                )
        except (
            AIProviderError,
            TimeoutError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            ValidationError,
        ) as error:
            logger.warning(
                "Gemini image analysis failed (provider_status=%s, error=%s)",
                error.status_code if isinstance(error, AIProviderError) else None,
                type(error).__name__,
            )
            raise ImageAnalysisUnavailable(
                "Gemini hiện không khả dụng hoặc không trả về kết quả hợp lệ; ảnh chưa được phân tích."
            ) from error

        assessment = self.evidence_engine.assess(
            output,
            provider.name,
            output.visible_text,
        )
        invalid = self._has_unusable_high_risk_evidence(output, assessment)
        return self._primary_result(
            output,
            assessment,
            invalid,
            CrossCheckStatus.NOT_REQUESTED,
            "Ảnh được phân tích bằng Gemini Vision.",
            AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
        )

    async def analyze_audio(
        self, audio: bytes, mime_type: str
    ) -> ScamAnalysisResponse:
        provider = self.audio_provider or self._configured_gemini()
        if provider is None:
            raise AudioAnalysisUnavailable(
                "Gemini chưa được bật hoặc chưa cấu hình API key; âm thanh chưa được phân tích."
            )

        try:
            async with self._semaphore:
                output: AudioModelAnalysisOutput = await asyncio.wait_for(
                    provider.analyze_audio(audio, mime_type),
                    timeout=self.configuration.AI_TIMEOUT_SECONDS,
                )
        except (
            AIProviderError,
            TimeoutError,
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            ValidationError,
        ) as error:
            logger.warning(
                "Gemini audio analysis failed (provider_status=%s, error=%s)",
                error.status_code if isinstance(error, AIProviderError) else None,
                type(error).__name__,
            )
            status_detail = (
                f" (HTTP {error.status_code})"
                if isinstance(error, AIProviderError) and error.status_code
                else ""
            )
            raise AudioAnalysisUnavailable(
                f"Gemini hiện không khả dụng{status_detail} hoặc không trả về kết quả hợp lệ; "
                "âm thanh chưa được phân tích."
            ) from error

        assessment = self.evidence_engine.assess(
            output,
            provider.name,
            output.transcript,
        )
        invalid = self._has_unusable_high_risk_evidence(output, assessment)
        result = self._primary_result(
            output,
            assessment,
            invalid,
            CrossCheckStatus.NOT_REQUESTED,
            "Âm thanh được phiên âm và phân tích bằng Gemini.",
            AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
        )
        return _redact_analysis_result(result)

    def _configured_openai(self) -> AIAnalysisProvider | None:
        if not self.configuration.AI_ENABLED or not self.configuration.OPENAI_API_KEY:
            return None
        return OpenAIProvider(self.configuration)

    def _configured_gemini(self) -> GeminiProvider | None:
        if not self.configuration.AI_ENABLED or not self.configuration.GEMINI_API_KEY:
            return None
        return GeminiProvider(self.configuration)

    @staticmethod
    def _single_provider_method(provider: AIAnalysisProvider) -> AnalysisMethod:
        if provider.name == "gemini":
            return AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS
        return AnalysisMethod.OPENAI_CONTEXTUAL_ANALYSIS

    @staticmethod
    def _has_unusable_high_risk_evidence(
        output: ModelAnalysisOutput,
        assessment: EvidenceAssessment,
    ) -> bool:
        return assessment.invalid_evidence_count > 0 or (
            output.risk_level == RiskLevel.HIGH_RISK and not assessment.findings
        )

    def _primary_result(
        self,
        output: ModelAnalysisOutput,
        assessment: EvidenceAssessment,
        invalid: bool,
        cross_check_status: CrossCheckStatus,
        cross_check_summary: str,
        analysis_method: AnalysisMethod,
    ) -> ScamAnalysisResponse:
        risk = output.risk_level
        summary = output.summary
        if invalid:
            risk = RiskLevel.SUSPICIOUS if assessment.findings else RiskLevel.INSUFFICIENT_DATA
            summary = "Một phần kết quả không có bằng chứng trích dẫn hợp lệ; cần kiểm chứng độc lập."
        elif risk == RiskLevel.LOW_RISK:
            summary = summary.rstrip(". ") + ". Rủi ro thấp không đồng nghĩa đã xác minh an toàn."
        return self._response(
            risk,
            summary,
            assessment.findings,
            output.recommendations,
            output.unverified_information,
            cross_check_status,
            cross_check_summary,
            analysis_method,
        )

    @staticmethod
    def _response(
        risk: RiskLevel,
        summary: str,
        findings: list[DetectedBehavior],
        recommendations: list[str],
        unverified_information: list[str],
        cross_status: CrossCheckStatus,
        cross_summary: str,
        method: AnalysisMethod,
    ) -> ScamAnalysisResponse:
        return ScamAnalysisResponse(
            risk_level=risk,
            summary=summary,
            detected_behaviors=findings,
            recommendations=recommendations[:7],
            unverified_information=unverified_information[:10],
            cross_check_status=cross_status,
            cross_check_summary=cross_summary,
            analysis_method=method,
            limitations=[
                "Đây là hỗ trợ phân tích, không xác nhận nội dung là lừa đảo hay hợp pháp.",
                "Danh tính người gửi, tổ chức, website và thông tin bên ngoài chưa được xác minh.",
                "AI có thể bỏ sót hoặc diễn giải sai; hãy xác minh qua kênh chính thức.",
            ],
        )

    @staticmethod
    def _unavailable(method: AnalysisMethod) -> ScamAnalysisResponse:
        summaries = {
            AnalysisMethod.EXTERNAL_ANALYSIS_NOT_CONSENTED: (
                "Chưa phân tích vì chưa có đồng ý gửi dữ liệu đến dịch vụ AI bên ngoài."
            ),
            AnalysisMethod.INPUT_LIMIT_EXCEEDED: (
                "Nội dung vượt giới hạn phân tích; chưa thể đưa ra đánh giá."
            ),
            AnalysisMethod.LLM_NOT_CONFIGURED: (
                "Chưa có nhà cung cấp AI được bật và cấu hình; hệ thống không tạo kết quả giả lập."
            ),
            AnalysisMethod.LLM_UNAVAILABLE: (
                "Dịch vụ AI không khả dụng hoặc trả kết quả không hợp lệ; chưa thể kết luận."
            ),
        }
        return ScamAnalysisResponse(
            risk_level=RiskLevel.INSUFFICIENT_DATA,
            summary=summaries[method],
            detected_behaviors=[],
            recommendations=[
                "Chưa cung cấp mật khẩu, mã OTP hoặc thông tin tài chính.",
                "Tự xác minh người gửi qua kênh chính thức mà bạn chủ động tìm được.",
            ],
            analysis_method=method,
            limitations=["Không có kết quả phân tích AI cho nội dung này."],
        )


def redact_sensitive_data(value: str) -> str:
    """Mask common Vietnamese contact details and explicitly labeled secrets."""
    value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL_ẨN]", value)
    value = re.sub(
        r"(?<!\w)(?:\+?84|0)(?:[\s.-]?\d){8,10}(?!\w)",
        "[SỐ_ĐIỆN_THOẠI_ẨN]",
        value,
    )
    value = re.sub(
        r"(?i)(số căn cước|căn cước|cccd|cmnd|số tài khoản|số thẻ)\s*(?:là|:|=)?\s*[\d -]{8,24}\d",
        r"\1: [SỐ_GIẤY_TỜ_HOẶC_TÀI_KHOẢN_ẨN]",
        value,
    )
    return re.sub(
        r"(?i)(mật khẩu|password|mã otp|otp|mã xác thực)\s*(?:là|:|=)\s*[^\s,;.]+",
        r"\1: [THÔNG_TIN_BÍ_MẬT_ẨN]",
        value,
    )


def _redact_analysis_result(result: ScamAnalysisResponse) -> ScamAnalysisResponse:
    """Avoid returning common sensitive details quoted or repeated by the model."""
    return result.model_copy(
        update={
            "summary": redact_sensitive_data(result.summary),
            "detected_behaviors": [
                behavior.model_copy(
                    update={
                        "name_vi": redact_sensitive_data(behavior.name_vi),
                        "description": redact_sensitive_data(behavior.description),
                        "evidence": redact_sensitive_data(behavior.evidence),
                        "explanation": redact_sensitive_data(behavior.explanation),
                    }
                )
                for behavior in result.detected_behaviors
            ],
            "recommendations": [
                redact_sensitive_data(recommendation)
                for recommendation in result.recommendations
            ],
            "unverified_information": [
                redact_sensitive_data(information)
                for information in result.unverified_information
            ],
        }
    )