"""Validates, normalizes, and merges evidence returned by AI providers."""

from dataclasses import dataclass

from app.schemas.scam_analysis import DetectedBehavior, ModelAnalysisOutput


BEHAVIOR_CATALOG: dict[str, tuple[str, str]] = {
    "URGENCY_PRESSURE": ("Tạo áp lực thời gian", "Thúc ép quyết định nhanh để giảm thời gian kiểm chứng."),
    "AUTHORITY_IMPERSONATION": ("Giả mạo cơ quan hoặc người có thẩm quyền", "Người gửi tự nhận đại diện cho một cơ quan hoặc người có thẩm quyền."),
    "THREATENED_CONSEQUENCES": ("Đe dọa hậu quả", "Dùng hậu quả tiêu cực để buộc người nhận làm theo."),
    "REWARD_BAIT": ("Dụ dỗ bằng phần thưởng", "Dùng phần thưởng hoặc lợi ích để thúc đẩy hành động."),
    "SECRECY_REQUEST": ("Yêu cầu giữ bí mật", "Ngăn người nhận chia sẻ hoặc xác minh với người đáng tin cậy."),
    "UNUSUAL_PAYMENT_REQUEST": ("Yêu cầu chuyển tiền bất thường", "Yêu cầu thanh toán hoặc chuyển tiền theo cách cần được xác minh."),
    "PERSONAL_DATA_HARVESTING": ("Thu thập dữ liệu cá nhân", "Yêu cầu thông tin cá nhân không rõ mục đích hoặc kênh bảo vệ."),
    "CREDENTIAL_OTP_THEFT": ("Lừa lấy mật khẩu hoặc OTP", "Yêu cầu thông tin đăng nhập hoặc mã xác thực bí mật."),
    "RELATIONSHIP_IMPERSONATION": ("Giả danh người quen", "Mạo nhận mối quan hệ quen biết để tạo lòng tin hoặc nhờ vả."),
    "EMOTIONAL_MANIPULATION": ("Thao túng cảm xúc", "Khai thác cảm xúc để làm giảm khả năng cân nhắc độc lập."),
    "SCARCITY_MANIPULATION": ("Tạo cảm giác khan hiếm", "Tạo ấn tượng cơ hội sắp hết để thúc ép quyết định."),
    "BRAND_IMPERSONATION": ("Giả mạo thương hiệu", "Nội dung có dấu hiệu mạo nhận thương hiệu chưa được xác minh."),
    "SUSPICIOUS_WEBSITE_REDIRECTION": ("Dẫn đến website đáng ngờ", "Dẫn người nhận đến một website cần được kiểm tra độc lập."),
    "UNTRUSTED_SOFTWARE_INSTALLATION": ("Yêu cầu cài phần mềm không rõ nguồn", "Thúc giục cài ứng dụng hoặc phần mềm chưa xác minh nguồn gốc."),
    "COMBINED_MANIPULATION": ("Kết hợp nhiều kỹ thuật thao túng", "Nhiều hành vi phối hợp nhằm dẫn người nhận đến hành động rủi ro."),
}


@dataclass(frozen=True)
class EvidenceAssessment:
    findings: list[DetectedBehavior]
    invalid_evidence_count: int


class EvidenceEngine:
    def assess(
        self,
        output: ModelAnalysisOutput,
        provider_name: str,
        source_text: str,
    ) -> EvidenceAssessment:
        findings: list[DetectedBehavior] = []
        invalid_count = 0
        for finding in output.detected_behaviors:
            if finding.evidence not in source_text:
                invalid_count += 1
                continue
            name_vi, description = BEHAVIOR_CATALOG.get(
                finding.type,
                (finding.name_vi, finding.description),
            )
            findings.append(
                DetectedBehavior(
                    type=finding.type,
                    name_vi=name_vi,
                    description=description,
                    evidence=finding.evidence,
                    explanation=finding.explanation,
                    supported_by=[provider_name],
                )
            )
        return EvidenceAssessment(findings, invalid_count)

    @staticmethod
    def merge(*groups: list[DetectedBehavior]) -> list[DetectedBehavior]:
        merged: dict[tuple[str, str], DetectedBehavior] = {}
        for group in groups:
            for finding in group:
                key = (finding.type, finding.evidence)
                previous = merged.get(key)
                if previous is None:
                    merged[key] = finding
                else:
                    merged[key] = previous.model_copy(
                        update={
                            "supported_by": sorted(
                                set(previous.supported_by + finding.supported_by)
                            )
                        }
                    )
        return list(merged.values())

    @staticmethod
    def merge_text(*groups: list[str]) -> list[str]:
        return list(dict.fromkeys(item for group in groups for item in group))