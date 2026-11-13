"""Validates, normalizes, and merges evidence returned by AI providers."""

import re
import unicodedata
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
    "CREDENTIAL_OTP_THEFT": ("Yêu cầu mật khẩu hoặc mã OTP", "Nội dung yêu cầu người nhận cung cấp thông tin đăng nhập hoặc mã xác thực bí mật."),
    "RELATIONSHIP_IMPERSONATION": ("Giả danh người quen", "Mạo nhận mối quan hệ quen biết để tạo lòng tin hoặc nhờ vả."),
    "EMOTIONAL_MANIPULATION": ("Thao túng cảm xúc", "Khai thác cảm xúc để làm giảm khả năng cân nhắc độc lập."),
    "SCARCITY_MANIPULATION": ("Tạo cảm giác khan hiếm", "Tạo ấn tượng cơ hội sắp hết để thúc ép quyết định."),
    "BRAND_IMPERSONATION": ("Giả mạo thương hiệu", "Nội dung có dấu hiệu mạo nhận thương hiệu chưa được xác minh."),
    "SUSPICIOUS_WEBSITE_REDIRECTION": ("Dẫn đến website đáng ngờ", "Dẫn người nhận đến một website cần được kiểm tra độc lập."),
    "UNTRUSTED_SOFTWARE_INSTALLATION": ("Yêu cầu cài phần mềm không rõ nguồn", "Thúc giục cài ứng dụng hoặc phần mềm chưa xác minh nguồn gốc."),
    "COMBINED_MANIPULATION": ("Kết hợp nhiều kỹ thuật thao túng", "Nhiều hành vi phối hợp nhằm dẫn người nhận đến hành động rủi ro."),
}

_CREDENTIAL_TERMS = (
    r"(?:mat\s*khau|password|ma\s*otp|otp|ma\s*xac\s*thuc|ma\s*bao\s*mat|"
    r"thong\s*tin\s*dang\s*nhap|thong\s*tin\s*tai\s*khoan)"
)
_CREDENTIAL_TERM = re.compile(rf"\b{_CREDENTIAL_TERMS}\b", re.IGNORECASE)
_REQUEST_ACTIONS = (
    r"(?:nhap|dien|cung\s*cap|gui|chia\s*se|chuyen\s*tiep|"
    r"tra\s*loi|doc|xac\s*nhan)"
)
_CREDENTIAL_REQUEST_PATTERNS = (
    re.compile(
        rf"\b{_REQUEST_ACTIONS}\b[^.!?;\n]{{0,100}}?\b{_CREDENTIAL_TERMS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_CREDENTIAL_TERMS}\b[^.!?;\n]{{0,100}}?\b{_REQUEST_ACTIONS}\b",
        re.IGNORECASE,
    ),
)
_NEGATED_REQUEST = re.compile(
    r"\b(?:khong|dung|cho|chua)\s+(?:bao\s*gio\s+)?"
    r"(?:(?:hay|vui\s*long)\s+)?(?:phai\s+)?"
    r"(?:nhap|dien|cung\s*cap|gui|chia\s*se|chuyen\s*tiep|"
    r"tra\s*loi|doc|xac\s*nhan)\b",
    re.IGNORECASE,
)
_SENDER_LABEL = re.compile(r"\bnguoi\s*$", re.IGNORECASE)
_SAFE_EDUCATIONAL_CONTEXT = re.compile(
    r"\b(?:canh\s*bao(?:\s+an\s*toan)?|bai\s*(?:bao|hoc|viet)|"
    r"vi\s*du(?:\s+minh\s*hoa)?|huong\s*dan|phong\s*tranh)\b.{0,240}\b"
    r"(?:mo\s*ta|phan\s*tich|trich|ke\s*gian|thu\s*doan|"
    r"lua\s*dao|khong\s+lam\s+theo|dung\s+lam\s+theo|khong\s+bam|"
    r"khong\s+nhap|khong\s+cung\s*cap|khong\s+chia\s*se)\b",
    re.IGNORECASE | re.DOTALL,
)
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_URGENCY = re.compile(
    r"\b(?:trong\s+(?:vong\s+)?\d+\s*(?:phut|gio|ngay)|"
    r"(?:con|chi\s+con)\s+\d+\s*(?:phut|gio|ngay)|"
    r"ngay\s+lap\s+tuc|truoc\s+\d{1,2}\s*[:h]\s*\d{2})\b",
    re.IGNORECASE,
)
_FINANCIAL_ORGANIZATION = re.compile(
    r"\b(?:ngan\s+hang|vi\s+dieu\s+tu|cong\s+ty\s+tai\s+chinh|"
    r"to\s+chuc\s+tin\s+dung|bao\s+hiem|tai\s+khoan\s+ngan\s+hang)\b",
    re.IGNORECASE,
)
_EXFILTRATION_ACTION = re.compile(
    rf"\b(?:gui|cung\s*cap|chia\s*se|chuyen\s*tiep|tra\s*loi|doc)\b"
    rf"[^.!?;\n]{{0,100}}?\b{_CREDENTIAL_TERMS}\b",
    re.IGNORECASE,
)


def _normalize_with_offsets(value: str) -> tuple[str, list[int], list[int]]:
    characters: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for index, original in enumerate(value):
        decomposed = unicodedata.normalize("NFD", original).replace("đ", "d").replace("Đ", "d")
        for character in decomposed.casefold():
            if unicodedata.combining(character):
                continue
            if character.isspace():
                if character == "\n":
                    while characters and characters[-1] == " ":
                        characters.pop()
                        starts.pop()
                        ends.pop()
                    if characters and characters[-1] != "\n":
                        characters.append("\n")
                        starts.append(index)
                        ends.append(index + 1)
                elif characters and characters[-1] in {" ", "\n"}:
                    if characters[-1] == " ":
                        ends[-1] = index + 1
                elif characters:
                    characters.append(" ")
                    starts.append(index)
                    ends.append(index + 1)
                continue
            characters.append(character)
            starts.append(index)
            ends.append(index + 1)
    return "".join(characters), starts, ends


def _excerpt_from_normalized(
    source: str,
    starts: list[int],
    ends: list[int],
    start: int,
    end: int,
) -> str:
    return source[starts[start] : ends[end - 1]]


def _find_explicit_credential_request(
    text: str,
    context: str = "",
) -> str | None:
    normalized, starts, ends = _normalize_with_offsets(text)
    normalized_context, _, _ = _normalize_with_offsets(context)

    candidates: list[re.Match[str]] = []
    for pattern in _CREDENTIAL_REQUEST_PATTERNS:
        offset = 0
        while match := pattern.search(normalized, offset):
            candidates.append(match)
            offset = match.start() + 1
    for match in sorted(candidates, key=lambda candidate: candidate.start()):
        clause_start = max(
            normalized.rfind(delimiter, 0, match.start())
            for delimiter in ".!?;\n"
        )
        clause = normalized[clause_start + 1 : match.end()]
        if _SENDER_LABEL.search(normalized[clause_start + 1 : match.start()]):
            continue
        if _NEGATED_REQUEST.search(clause):
            continue
        context_start = (
            normalized_context.find(match.group())
            if normalized_context and normalized_context != normalized
            else match.start()
        )
        if context_start >= 0:
            context_clause_start = max(
                normalized_context.rfind(delimiter, 0, context_start)
                for delimiter in ".!?;\n"
            )
            context_clause = normalized_context[
                context_clause_start + 1 : context_start + len(match.group())
            ]
            line_start = normalized_context.rfind("\n", 0, context_start) + 1
            line_end = normalized_context.find(
                "\n", context_start + len(match.group())
            )
            if line_end < 0:
                line_end = len(normalized_context)
            context_window = normalized_context[
                max(line_start, context_start - 240) : min(
                    line_end,
                    context_start + len(match.group()) + 240,
                )
            ]
            if _NEGATED_REQUEST.search(context_clause):
                continue
            if _SAFE_EDUCATIONAL_CONTEXT.search(context_window):
                continue
        elif _SAFE_EDUCATIONAL_CONTEXT.search(normalized):
            continue

        match_end = match.end()
        while True:
            next_term = _CREDENTIAL_TERM.search(normalized, match_end, match_end + 32)
            if next_term is None:
                break
            connector = normalized[match_end : next_term.start()]
            if not re.fullmatch(r"\s*(?:(?:,|and|va|cung|hoac)\s*)+", connector):
                break
            match_end = next_term.end()
        return _excerpt_from_normalized(text, starts, ends, match.start(), match_end)
    return None


def _is_explicit_credential_request(text: str, context: str = "") -> bool:
    return _find_explicit_credential_request(text, context) is not None


def _extract_url(text: str) -> str | None:
    match = _URL.search(text)
    if match is None:
        return None
    return match.group().rstrip(".,;:!?)]}")


def _context_around_evidence(source: str, evidence: str) -> str:
    location = source.find(evidence)
    if location < 0:
        return source
    start = max(0, location - 240)
    end = min(len(source), location + len(evidence) + 240)
    return source[start:end]


def _extract_urgency(text: str) -> str | None:
    normalized, starts, ends = _normalize_with_offsets(text)
    match = _URGENCY.search(normalized)
    if match is None:
        return None
    return _excerpt_from_normalized(text, starts, ends, match.start(), match.end())


def _has_financial_organization_reference(text: str) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    return _FINANCIAL_ORGANIZATION.search(normalized) is not None


def _is_credential_exfiltration_request(text: str) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    return _EXFILTRATION_ACTION.search(normalized) is not None


def _credential_labels(text: str) -> str:
    normalized, _, _ = _normalize_with_offsets(text)
    has_password = re.search(r"\b(?:mat\s*khau|password)\b", normalized) is not None
    has_otp = re.search(r"\b(?:ma\s*otp|otp)\b", normalized) is not None
    if has_password and has_otp:
        return "mật khẩu và mã OTP"
    if has_password:
        return "mật khẩu"
    if has_otp:
        return "mã OTP"
    return "thông tin đăng nhập"


def _credential_request_uses_entry_verb(text: str) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    return re.search(r"\b(?:nhap|dien)\b", normalized) is not None


@dataclass(frozen=True)
class EvidenceAssessment:
    findings: list[DetectedBehavior]
    invalid_evidence_count: int


class EvidenceEngine:
    @staticmethod
    def is_explicit_credential_request(text: str, context: str = "") -> bool:
        return _is_explicit_credential_request(text, context)

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
            behavior_type = finding.type
            if _is_explicit_credential_request(excerpt, source_text):
                behavior_type = "CREDENTIAL_OTP_THEFT"
            elif behavior_type == "CREDENTIAL_OTP_THEFT":
                continue
            name_vi, description = BEHAVIOR_CATALOG.get(
                behavior_type,
                (
                    "Dấu hiệu cần kiểm tra",
                    "Đoạn trích này cần được xem xét trong ngữ cảnh.",
                ),
            )
            findings.append(
                DetectedBehavior(
                    type=behavior_type,
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
        credential_evidence = _find_explicit_credential_request(
            source_text,
            source_text,
        )
        related_context = (
            _context_around_evidence(source_text, credential_evidence)
            if credential_evidence is not None
            else ""
        )
        url_evidence = _extract_url(related_context)
        urgency_evidence = _extract_urgency(related_context)
        credential_context_is_suspicious = (
            credential_evidence is not None
            and (
                _is_credential_exfiltration_request(credential_evidence)
                or url_evidence is not None
                or (
                    _has_financial_organization_reference(related_context)
                    and urgency_evidence is not None
                )
            )
        )
        if credential_context_is_suspicious and credential_evidence is not None:
            normalized_credential, _, _ = _normalize_with_offsets(
                credential_evidence
            )
            matching_credentials = [
                finding
                for finding in findings
                if finding.type == "CREDENTIAL_OTP_THEFT"
                and (
                    normalized_credential
                    in _normalize_with_offsets(finding.evidence)[0]
                    or _normalize_with_offsets(finding.evidence)[0]
                    in normalized_credential
                )
            ]
            if not any(
                len(_normalize_with_offsets(finding.evidence)[0])
                >= len(normalized_credential)
                for finding in matching_credentials
            ):
                findings = [
                    finding
                    for finding in findings
                    if finding not in matching_credentials
                ]
                findings.insert(
                    0,
                    DetectedBehavior(
                        type="CREDENTIAL_OTP_THEFT",
                        name_vi=BEHAVIOR_CATALOG["CREDENTIAL_OTP_THEFT"][0],
                        description=BEHAVIOR_CATALOG["CREDENTIAL_OTP_THEFT"][1],
                        evidence=credential_evidence,
                        explanation=(
                            "Dấu hiệu này dựa trên đoạn trích; nội dung yêu cầu "
                            "nhập hoặc cung cấp thông tin xác thực."
                        ),
                        supported_by=["evidence_engine"],
                    ),
                )
            if url_evidence:
                findings.append(
                    DetectedBehavior(
                        type="SUSPICIOUS_WEBSITE_REDIRECTION",
                        name_vi=BEHAVIOR_CATALOG["SUSPICIOUS_WEBSITE_REDIRECTION"][0],
                        description=BEHAVIOR_CATALOG["SUSPICIOUS_WEBSITE_REDIRECTION"][1],
                        evidence=url_evidence,
                        explanation=(
                            "Đường dẫn xuất hiện cùng yêu cầu thông tin xác thực; "
                            "chưa xác minh website."
                        ),
                        supported_by=["evidence_engine"],
                    )
                )
            if urgency_evidence:
                findings.append(
                    DetectedBehavior(
                        type="URGENCY_PRESSURE",
                        name_vi=BEHAVIOR_CATALOG["URGENCY_PRESSURE"][0],
                        description=BEHAVIOR_CATALOG["URGENCY_PRESSURE"][1],
                        evidence=urgency_evidence,
                        explanation=(
                            "Nội dung nêu thời hạn hoặc yêu cầu xử lý gấp; "
                            "đoạn trích không xác minh hậu quả thực tế."
                        ),
                        supported_by=["evidence_engine"],
                    )
                )
        return EvidenceAssessment(findings, invalid_count)

    @staticmethod
    def has_explicit_credential_request(text: str) -> bool:
        return _find_explicit_credential_request(text, text) is not None

    @staticmethod
    def extract_url(text: str) -> str | None:
        return _extract_url(text)

    @staticmethod
    def related_context(source: str, evidence: str) -> str:
        return _context_around_evidence(source, evidence)

    @staticmethod
    def extract_urgency(text: str) -> str | None:
        return _extract_urgency(text)

    @staticmethod
    def has_financial_organization_reference(text: str) -> bool:
        return _has_financial_organization_reference(text)

    @staticmethod
    def credential_labels(text: str) -> str:
        return _credential_labels(text)

    @staticmethod
    def credential_request_uses_entry_verb(text: str) -> bool:
        return _credential_request_uses_entry_verb(text)

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