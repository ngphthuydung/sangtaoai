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
    @staticmethod
    def _find_verbatim_excerpt(source: str, quote: str) -> str | None:
        def compact(value: str) -> tuple[str, list[int], list[int]]:
            characters: list[str] = []
            starts: list[int] = []
            ends: list[int] = []
            whitespace_start: int | None = None
            for index, character in enumerate(value):
                if character.isspace():
                    if whitespace_start is None:
                        whitespace_start = index
                    continue
                if whitespace_start is not None:
                    if characters:
                        characters.append(" ")
                        starts.append(whitespace_start)
                        ends.append(index)
                    whitespace_start = None
                characters.append(character)
                starts.append(index)
                ends.append(index + 1)
            return "".join(characters), starts, ends

        source_text, source_starts, source_ends = compact(source)
        quote_text, _, _ = compact(quote)
        if not quote_text:
            return None
        location = source_text.find(quote_text)
        if location < 0:
            return None
        start = source_starts[location]
        end = source_ends[location + len(quote_text) - 1]
        return source[start:end]

    def assess(
        self,
        output: ModelAnalysisOutput,
        provider_name: str,
        source_text: str,
    ) -> EvidenceAssessment:
        findings: list[DetectedBehavior] = []
        invalid_count = 0
        for finding in output.detected_behaviors:
            excerpt = self._find_verbatim_excerpt(source_text, finding.evidence)
            if excerpt is None:
                invalid_count += 1
                continue
            name_vi, description = BEHAVIOR_CATALOG.get(
                finding.type,
                (
                    "Dấu hiệu cần kiểm tra",
                    "Đoạn trích này cần được xem xét trong ngữ cảnh.",
                ),
            )
            findings.append(
                DetectedBehavior(
                    type=finding.type,
                    name_vi=name_vi,
                    description=description,
                    evidence=excerpt,
                    explanation=(
                        "Dấu hiệu này dựa trên đoạn trích ở trên; danh tính người gửi "
                        "và sự việc bên ngoài chưa được xác minh."
                    ),
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