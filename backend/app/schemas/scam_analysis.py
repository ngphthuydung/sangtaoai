"""Request and response models for contextual scam analysis."""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RiskLevel(str, Enum):
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class AnalysisStatus(str, Enum):
    COMPLETED = "COMPLETED"
    NOT_ANALYZED = "NOT_ANALYZED"
    FAILED = "FAILED"


class AnalysisFailureReason(str, Enum):
    AI_UNAVAILABLE = "AI_UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    TIMEOUT = "TIMEOUT"
    HTTP_ERROR = "HTTP_ERROR"


class TranscriptionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class BehaviorType(str, Enum):
    URGENCY_PRESSURE = "URGENCY_PRESSURE"
    AUTHORITY_IMPERSONATION = "AUTHORITY_IMPERSONATION"
    THREATENED_CONSEQUENCES = "THREATENED_CONSEQUENCES"
    REWARD_BAIT = "REWARD_BAIT"
    SECRECY_REQUEST = "SECRECY_REQUEST"
    UNUSUAL_PAYMENT_REQUEST = "UNUSUAL_PAYMENT_REQUEST"
    PERSONAL_DATA_HARVESTING = "PERSONAL_DATA_HARVESTING"
    CREDENTIAL_OTP_THEFT = "CREDENTIAL_OTP_THEFT"
    RELATIONSHIP_IMPERSONATION = "RELATIONSHIP_IMPERSONATION"
    EMOTIONAL_MANIPULATION = "EMOTIONAL_MANIPULATION"
    SCARCITY_MANIPULATION = "SCARCITY_MANIPULATION"
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    SUSPICIOUS_WEBSITE_REDIRECTION = "SUSPICIOUS_WEBSITE_REDIRECTION"
    UNTRUSTED_SOFTWARE_INSTALLATION = "UNTRUSTED_SOFTWARE_INSTALLATION"
    COMBINED_MANIPULATION = "COMBINED_MANIPULATION"


class AnalysisMethod(str, Enum):
    OPENAI_CONTEXTUAL_ANALYSIS = "OPENAI_CONTEXTUAL_ANALYSIS"
    GEMINI_CONTEXTUAL_ANALYSIS = "GEMINI_CONTEXTUAL_ANALYSIS"
    HYBRID_CONTEXTUAL_ANALYSIS = "HYBRID_CONTEXTUAL_ANALYSIS"
    LLM_NOT_CONFIGURED = "LLM_NOT_CONFIGURED"
    EXTERNAL_ANALYSIS_NOT_CONSENTED = "EXTERNAL_ANALYSIS_NOT_CONSENTED"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    INPUT_LIMIT_EXCEEDED = "INPUT_LIMIT_EXCEEDED"


class CrossCheckStatus(str, Enum):
    NOT_REQUESTED = "NOT_REQUESTED"
    CONFIRMED = "CONFIRMED"
    DISAGREEMENT = "DISAGREEMENT"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class VerificationStatus(str, Enum):
    NOT_VERIFIED = "NOT_VERIFIED"


class ScamAnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str = Field(min_length=1, max_length=12000)
    context: str | None = Field(default=None, max_length=4000)
    allow_external_processing: bool = False

    @field_validator("content")
    @classmethod
    def content_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Nội dung cần phân tích không được để trống")
        return value


class DetectedBehavior(BaseModel):
    type: str
    name_vi: str
    description: str
    evidence: str
    explanation: str
    supported_by: list[str] = Field(default_factory=list)


class ScamAnalysisResponse(BaseModel):
    risk_level: RiskLevel
    summary: str
    detected_behaviors: list[DetectedBehavior] = Field(max_length=30)
    recommendations: list[str] = Field(max_length=7)
    analysis_status: AnalysisStatus = AnalysisStatus.COMPLETED
    analysis_failure_reason: AnalysisFailureReason | None = None
    transcription_status: TranscriptionStatus | None = None
    unverified_information: list[str] = Field(default_factory=list, max_length=10)
    verification_status: VerificationStatus = VerificationStatus.NOT_VERIFIED
    cross_check_status: CrossCheckStatus = CrossCheckStatus.NOT_REQUESTED
    cross_check_summary: str = "Chưa thực hiện kiểm tra chéo."
    analysis_method: AnalysisMethod
    limitations: list[str] = Field(default_factory=list, max_length=10)


class ModelBehaviorFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,63}$")
    name_vi: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    evidence: str = Field(min_length=1, max_length=1000)
    explanation: str = Field(min_length=1, max_length=1200)


class ModelAnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_level: RiskLevel
    summary: str = Field(min_length=1, max_length=1600)
    detected_behaviors: list[ModelBehaviorFinding] = Field(max_length=30)
    recommendations: list[str] = Field(max_length=7)
    unverified_information: list[str] = Field(default_factory=list, max_length=10)


class ImageModelAnalysisOutput(ModelAnalysisOutput):
    visible_text: str = Field(max_length=12000)


class AudioModelAnalysisOutput(ModelAnalysisOutput):
    transcript: str = Field(max_length=12000)
    transcription_status: TranscriptionStatus | None = None
