"""Hybrid AI orchestration for contextual scam analysis."""

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from typing import TypeVar

from pydantic import ValidationError

from app.core.config import Settings, settings
from app.core.request_diagnostics import record_provider_failure, record_retry
from app.schemas.scam_analysis import (
    AnalysisFailureReason,
    AnalysisStatus,
    AnalysisMethod,
    AudioModelAnalysisOutput,
    CrossCheckStatus,
    DetectedBehavior,
    ImageModelAnalysisOutput,
    ImageTextStatus,
    ModelAnalysisOutput,
    RiskLevel,
    ScamAnalysisRequest,
    ScamAnalysisResponse,
    TranscriptionStatus,
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
AI_FAILURE_MESSAGE = "Không thể phân tích do dịch vụ AI gặp sự cố."
AI_RETRY_ATTEMPTS = 2
AI_RETRY_DELAY_SECONDS = 0.25
AI_TOTAL_TIMEOUT_CAP_SECONDS = 55.0
ResultT = TypeVar("ResultT")


class ImageAnalysisUnavailable(Exception):
    """Raised when Gemini cannot provide an image analysis."""


class AudioAnalysisUnavailable(Exception):
    """Raised when Gemini cannot provide an audio analysis."""


def _record_provider_error(error: Exception) -> None:
    if isinstance(error, AIProviderError):
        if error.status_code is not None:
            category = "provider_http_error"
        elif error.failure_reason == AnalysisFailureReason.TIMEOUT:
            category = "provider_timeout"
        elif error.failure_reason == AnalysisFailureReason.INVALID_RESPONSE:
            category = "invalid_provider_response"
        else:
            category = "provider_connection_error"
        record_provider_failure(category, error.status_code)
    elif isinstance(error, TimeoutError):
        record_provider_failure("provider_timeout")
    elif isinstance(error, (ValueError, KeyError, IndexError, TypeError, ValidationError)):
        record_provider_failure("invalid_provider_response")
    else:
        record_provider_failure("provider_error")


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

    async def _call_provider_with_retry(
        self,
        provider_name: str,
        operation: Callable[[], Awaitable[ResultT]],
    ) -> ResultT:
        loop = asyncio.get_running_loop()
        timeout_budget = min(
            self.configuration.AI_TIMEOUT_SECONDS * AI_RETRY_ATTEMPTS
            + AI_RETRY_DELAY_SECONDS,
            AI_TOTAL_TIMEOUT_CAP_SECONDS,
        )
        deadline = loop.time() + timeout_budget
        last_error: AIProviderError | None = None

        for attempt in range(AI_RETRY_ATTEMPTS):
            remaining = deadline - loop.time()
            if remaining <= 0:
                break

            try:
                return await asyncio.wait_for(
                    operation(),
                    timeout=min(self.configuration.AI_TIMEOUT_SECONDS, remaining),
                )
            except AIProviderError as error:
                last_error = error
                retryable = error.retryable
            except TimeoutError:
                last_error = AIProviderError(
                    "Nhà cung cấp AI hết thời gian chờ",
                    failure_reason=AnalysisFailureReason.TIMEOUT,
                    retryable=True,
                )
                retryable = True

            if not retryable or attempt + 1 == AI_RETRY_ATTEMPTS:
                _record_provider_error(last_error)
                raise last_error

            remaining = deadline - loop.time()
            if remaining <= AI_RETRY_DELAY_SECONDS:
                break
            record_retry()
            logger.info(
                "%s transient failure (reason=%s, status=%s); retrying once",
                provider_name,
                last_error.failure_reason.value,
                last_error.status_code,
            )
            await asyncio.sleep(AI_RETRY_DELAY_SECONDS)

        if last_error is not None:
            _record_provider_error(last_error)
            raise last_error
        raise AIProviderError(
            "AI provider request exceeded its time budget",
            failure_reason=AnalysisFailureReason.TIMEOUT,
        )

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
            return self._unavailable(
                AnalysisMethod.LLM_NOT_CONFIGURED,
                AnalysisFailureReason.AI_UNAVAILABLE,
            )

        safe_content = redact_sensitive_data(request.content)
        safe_context = redact_sensitive_data(request.context) if request.context else None
        evidence_source = safe_content + ("\n" + safe_context if safe_context else "")

        async with self._semaphore:
            try:
                primary = await asyncio.wait_for(
                    self._call_provider_with_retry(
                        primary_provider.name,
                        lambda: primary_provider.analyze(safe_content, safe_context),
                    ),
                    timeout=AI_TOTAL_TIMEOUT_CAP_SECONDS + 1,
                )
            except AIProviderError as error:
                _record_provider_error(error)
                logger.warning(
                    "%s analysis failed (failure_reason=%s, provider_status=%s, error=%s)",
                    primary_provider.name,
                    error.failure_reason.value,
                    error.status_code if isinstance(error, AIProviderError) else None,
                    type(error).__name__,
                )
                return self._unavailable(
                    AnalysisMethod.LLM_UNAVAILABLE,
                    error.failure_reason,
                )
            except TimeoutError as error:
                record_provider_failure("provider_timeout")
                logger.warning(
                    "%s analysis failed (failure_reason=%s, error=%s)",
                    primary_provider.name,
                    AnalysisFailureReason.TIMEOUT.value,
                    type(error).__name__,
                )
                return self._unavailable(
                    AnalysisMethod.LLM_UNAVAILABLE,
                    AnalysisFailureReason.TIMEOUT,
                )
            except (ValueError, KeyError, IndexError, TypeError, ValidationError) as error:
                record_provider_failure("invalid_provider_response")
                logger.warning(
                    "%s analysis failed (failure_reason=%s, error=%s)",
                    primary_provider.name,
                    AnalysisFailureReason.INVALID_RESPONSE.value,
                    type(error).__name__,
                )
                return self._unavailable(
                    AnalysisMethod.LLM_UNAVAILABLE,
                    AnalysisFailureReason.INVALID_RESPONSE,
                )

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
            raise ImageAnalysisUnavailable(AI_FAILURE_MESSAGE)

        try:
            async with self._semaphore:
                output: ImageModelAnalysisOutput = await asyncio.wait_for(
                    self._call_provider_with_retry(
                        provider.name,
                        lambda: provider.analyze_image(image, mime_type),
                    ),
                    timeout=AI_TOTAL_TIMEOUT_CAP_SECONDS + 1,
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
            _record_provider_error(error)
            logger.warning(
                "Gemini image analysis failed (provider_status=%s, error=%s)",
                error.status_code if isinstance(error, AIProviderError) else None,
                type(error).__name__,
            )
            raise ImageAnalysisUnavailable(
                AI_FAILURE_MESSAGE
            ) from error

        assessment = self.evidence_engine.assess(
            output,
            provider.name,
            output.visible_text,
        )
        text_status = output.visible_text_status or (
            ImageTextStatus.PARTIAL
            if output.visible_text.strip()
            else ImageTextStatus.FAILED
        )
        if text_status == ImageTextStatus.FAILED or not output.visible_text.strip():
            return self._response(
                RiskLevel.INSUFFICIENT_DATA,
                "Chưa đọc rõ chữ trong ảnh để đánh giá. Đây không phải kết luận an toàn.",
                [],
                [
                    "Hãy gửi ảnh rõ hơn, không bị mờ hoặc che khuất.",
                    "Chưa làm theo yêu cầu chuyển tiền hay cung cấp thông tin bí mật.",
                ],
                [],
                CrossCheckStatus.NOT_REQUESTED,
                "Không đọc được nội dung cần thiết trong ảnh.",
                AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
            ).model_copy(
                update={
                    "limitations": [
                        "Không đọc được chữ cần thiết trong ảnh.",
                        "Danh tính người gửi và thông tin bên ngoài chưa được xác minh.",
                    ]
                }
            )
        invalid = self._has_unusable_high_risk_evidence(output, assessment)
        result = self._primary_result(
            output,
            assessment,
            invalid,
            CrossCheckStatus.NOT_REQUESTED,
            "Ảnh được phân tích bằng Gemini Vision.",
            AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
            evidence_complete=text_status == ImageTextStatus.COMPLETED,
        )
        if text_status == ImageTextStatus.PARTIAL:
            result = result.model_copy(
                update={
                    "summary": result.summary
                    + " Chỉ đọc được một phần chữ trong ảnh.",
                    "limitations": [
                        *result.limitations,
                        "Một phần chữ trong ảnh chưa đọc được và chưa được đánh giá.",
                    ][:10],
                }
            )
        return result

    async def analyze_audio(
        self, audio: bytes, mime_type: str
    ) -> ScamAnalysisResponse:
        provider = self.audio_provider or self._configured_gemini()
        if provider is None:
            raise AudioAnalysisUnavailable(AI_FAILURE_MESSAGE)

        try:
            async with self._semaphore:
                output: AudioModelAnalysisOutput = await asyncio.wait_for(
                    self._call_provider_with_retry(
                        provider.name,
                        lambda: provider.analyze_audio(audio, mime_type),
                    ),
                    timeout=AI_TOTAL_TIMEOUT_CAP_SECONDS + 1,
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
            _record_provider_error(error)
            logger.warning(
                "Gemini audio analysis failed (provider_status=%s, error=%s)",
                error.status_code if isinstance(error, AIProviderError) else None,
                type(error).__name__,
            )
            raise AudioAnalysisUnavailable(
                AI_FAILURE_MESSAGE
            ) from error

        assessment = self.evidence_engine.assess(
            output,
            provider.name,
            output.transcript,
        )
        transcription_status = output.transcription_status or (
            TranscriptionStatus.PARTIAL
            if output.transcript.strip()
            else TranscriptionStatus.FAILED
        )
        if transcription_status == TranscriptionStatus.FAILED:
            return self._response(
                RiskLevel.INSUFFICIENT_DATA,
                "Không nghe rõ lời nói để phân tích. Đây không phải kết luận an toàn.",
                [],
                [
                    "Hãy thử gửi bản ghi âm rõ hơn hoặc chép lại nội dung để kiểm tra.",
                    "Chưa cung cấp mật khẩu, mã OTP hoặc thông tin tài chính.",
                ],
                [],
                CrossCheckStatus.NOT_REQUESTED,
                "Không thể nhận dạng lời nói trong bản ghi.",
                AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
            ).model_copy(update={"transcription_status": transcription_status})
        if (
            transcription_status == TranscriptionStatus.PARTIAL
            and not assessment.findings
        ):
            return self._response(
                RiskLevel.INSUFFICIENT_DATA,
                "Chỉ nghe rõ một phần bản ghi; chưa đủ căn cứ để đánh giá toàn bộ nội dung.",
                [],
                [
                    "Hãy gửi lại bản ghi rõ hơn hoặc chép lại phần lời nói cần kiểm tra.",
                    "Chưa cung cấp mật khẩu, mã OTP hoặc thông tin tài chính.",
                ],
                [],
                CrossCheckStatus.NOT_REQUESTED,
                "Bản ghi chỉ được nghe rõ một phần.",
                AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
            ).model_copy(update={"transcription_status": transcription_status})
        invalid = self._has_unusable_high_risk_evidence(output, assessment)
        result = self._primary_result(
            output,
            assessment,
            invalid,
            CrossCheckStatus.NOT_REQUESTED,
            "Âm thanh được phiên âm và phân tích bằng Gemini.",
            AnalysisMethod.GEMINI_CONTEXTUAL_ANALYSIS,
            evidence_complete=transcription_status == TranscriptionStatus.COMPLETED,
        )
        if transcription_status == TranscriptionStatus.PARTIAL:
            result = result.model_copy(
                update={
                    "summary": result.summary
                    + " Bản ghi chỉ nghe rõ một phần; phần còn lại chưa được đánh giá."
                }
            )
        return _redact_analysis_result(
            result.model_copy(update={"transcription_status": transcription_status})
        )

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
        evidence_complete: bool = True,
    ) -> ScamAnalysisResponse:
        finding_types = {finding.type for finding in assessment.findings}
        high_risk_combination = (
            "AUTHORITY_IMPERSONATION" in finding_types
            and "UNUSUAL_PAYMENT_REQUEST" in finding_types
            and bool(
                finding_types
                & {"THREATENED_CONSEQUENCES", "URGENCY_PRESSURE"}
            )
        )
        high_risk_supported = (
            output.risk_level == RiskLevel.HIGH_RISK
            and (
                "CREDENTIAL_OTP_THEFT" in finding_types
                or high_risk_combination
            )
        )
        if high_risk_supported and evidence_complete:
            risk = RiskLevel.HIGH_RISK
        elif (
            assessment.findings
            and output.risk_level
            in {RiskLevel.HIGH_RISK, RiskLevel.SUSPICIOUS}
        ):
            risk = RiskLevel.SUSPICIOUS
        elif (
            assessment.findings
            and output.risk_level == RiskLevel.LOW_RISK
            and (
                "CREDENTIAL_OTP_THEFT" in finding_types
                or high_risk_combination
            )
        ):
            risk = RiskLevel.SUSPICIOUS
        elif (
            output.risk_level == RiskLevel.LOW_RISK
            and not assessment.findings
            and not invalid
            and evidence_complete
        ):
            risk = RiskLevel.LOW_RISK
        else:
            risk = RiskLevel.INSUFFICIENT_DATA

        if risk == RiskLevel.HIGH_RISK:
            finding = next(
                (
                    item
                    for item in assessment.findings
                    if item.type == "CREDENTIAL_OTP_THEFT"
                ),
                assessment.findings[0],
            )
            summary = (
                f"Có dấu hiệu nguy cơ cao: {finding.name_vi}. "
                f"Nội dung trích dẫn: “{finding.evidence}”"
            )
        elif risk == RiskLevel.SUSPICIOUS:
            finding = assessment.findings[0]
            summary = (
                f"Có dấu hiệu cần kiểm tra: {finding.name_vi}. "
                f"Nội dung trích dẫn: “{finding.evidence}”"
            )
        elif risk == RiskLevel.LOW_RISK:
            summary = (
                "Chưa thấy dấu hiệu đáng ngờ rõ ràng trong nội dung đã gửi. "
                "Điều này không đồng nghĩa nội dung đã được xác minh an toàn."
            )
        elif invalid:
            summary = (
                "Chưa đủ bằng chứng cụ thể trong nội dung đã gửi để kết luận. "
                "Một số trích dẫn do AI đưa ra không khớp nguyên văn."
            )
        elif assessment.findings:
            finding = assessment.findings[0]
            summary = (
                "Có đoạn trích cần lưu ý, nhưng chưa đủ thông tin để xác định mức độ: "
                f"“{finding.evidence}”"
            )
        else:
            summary = "Chưa đủ bằng chứng cụ thể trong nội dung đã gửi để kết luận."
        return self._response(
            risk,
            summary,
            assessment.findings,
            self._recommended_actions(risk, finding_types),
            ["Danh tính người gửi và thông tin bên ngoài chưa được xác minh."],
            cross_check_status,
            cross_check_summary,
            analysis_method,
        )

    @staticmethod
    def _recommended_actions(
        risk: RiskLevel,
        finding_types: set[str],
    ) -> list[str]:
        if risk == RiskLevel.HIGH_RISK:
            if "CREDENTIAL_OTP_THEFT" in finding_types:
                return [
                    "Không cung cấp OTP hoặc mật khẩu. Nếu đã gửi, hãy liên hệ tổ chức liên quan qua kênh chính thức."
                ]
            return [
                "Không chuyển tiền theo yêu cầu này. Tự liên hệ cơ quan qua số điện thoại chính thức."
            ]
        if risk == RiskLevel.SUSPICIOUS:
            actions: list[str] = []
            if "CREDENTIAL_OTP_THEFT" in finding_types:
                actions.append("Không chia sẻ OTP hoặc mật khẩu; tự liên hệ tổ chức qua kênh chính thức.")
            if "UNUSUAL_PAYMENT_REQUEST" in finding_types:
                actions.append("Tạm dừng thanh toán; xác minh qua ứng dụng hoặc số điện thoại chính thức.")
            if "SUSPICIOUS_WEBSITE_REDIRECTION" in finding_types:
                actions.append("Không mở liên kết hoặc nhập thông tin; tự vào ứng dụng chính thức.")
            if "REWARD_BAIT" in finding_types:
                actions.append("Không chuyển tiền hoặc nộp phí để nhận lợi ích trước khi xác minh.")
            if "AUTHORITY_IMPERSONATION" in finding_types:
                actions.append("Tự gọi số chính thức của cơ quan để xác minh.")
            if "UNTRUSTED_SOFTWARE_INSTALLATION" in finding_types:
                actions.append("Không cài ứng dụng theo yêu cầu khi chưa xác minh nguồn.")
            return (actions or ["Tạm dừng làm theo yêu cầu và xác minh người gửi qua kênh độc lập."])[:2]
        if risk == RiskLevel.LOW_RISK:
            return [
                "Chưa thấy dấu hiệu rõ ràng. Nếu được yêu cầu chuyển tiền hoặc cung cấp thông tin bí mật, hãy tự xác minh qua kênh chính thức."
            ]
        return [
            "Hãy bổ sung nội dung liên quan hoặc gửi ảnh, âm thanh rõ hơn để kiểm tra.",
            "Tạm hoãn chuyển tiền hoặc chia sẻ thông tin bí mật cho đến khi xác minh.",
        ]

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
    def _unavailable(
        method: AnalysisMethod,
        failure_reason: AnalysisFailureReason | None = None,
    ) -> ScamAnalysisResponse:
        summaries = {
            AnalysisMethod.EXTERNAL_ANALYSIS_NOT_CONSENTED: (
                "Chưa phân tích vì chưa có đồng ý gửi dữ liệu đến dịch vụ AI bên ngoài."
            ),
            AnalysisMethod.INPUT_LIMIT_EXCEEDED: (
                "Nội dung vượt giới hạn phân tích; chưa thể đưa ra đánh giá."
            ),
            AnalysisMethod.LLM_NOT_CONFIGURED: AI_FAILURE_MESSAGE,
            AnalysisMethod.LLM_UNAVAILABLE: AI_FAILURE_MESSAGE,
        }
        failed = method in {
            AnalysisMethod.LLM_NOT_CONFIGURED,
            AnalysisMethod.LLM_UNAVAILABLE,
        }
        return ScamAnalysisResponse(
            risk_level=RiskLevel.INSUFFICIENT_DATA,
            summary=summaries[method],
            detected_behaviors=[],
            recommendations=[
                "Chưa cung cấp mật khẩu, mã OTP hoặc thông tin tài chính.",
                "Tự xác minh người gửi qua kênh chính thức mà bạn chủ động tìm được.",
            ],
            analysis_status=(
                AnalysisStatus.FAILED if failed else AnalysisStatus.NOT_ANALYZED
            ),
            analysis_failure_reason=(
                failure_reason or AnalysisFailureReason.AI_UNAVAILABLE
                if failed
                else None
            ),
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