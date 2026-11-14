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
    r"ma\s*pin|pin|thong\s*tin\s*dang\s*nhap|thong\s*tin\s*tai\s*khoan)"
)
_FINANCIAL_DATA_TERMS = (
    r"(?:so\s*the|thong\s*tin\s*the|the\s*(?:tin\s*dung|ghi\s*no)|"
    r"cvv|cvc|ma\s*pin|pin|ngay\s*het\s*han|han\s*su\s*dung)"
)
_SENSITIVE_TERMS = rf"(?:{_CREDENTIAL_TERMS}|{_FINANCIAL_DATA_TERMS})"
_CREDENTIAL_TERM = re.compile(rf"\b{_CREDENTIAL_TERMS}\b", re.IGNORECASE)
_SENSITIVE_TERM = re.compile(rf"\b{_SENSITIVE_TERMS}\b", re.IGNORECASE)
_REQUEST_ACTIONS = (
    r"(?:nhap|dien|cung\s*cap|gui|chia\s*se|chuyen\s*tiep|"
    r"tra\s*loi|doc|xac\s*nhan)"
)
_SENSITIVE_REQUEST_PATTERNS = (
    re.compile(
        rf"\b{_REQUEST_ACTIONS}\b[^.!?;\n]{{0,100}}?\b{_SENSITIVE_TERMS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_SENSITIVE_TERMS}\b[^.!?;\n]{{0,100}}?\b{_REQUEST_ACTIONS}\b",
        re.IGNORECASE,
    ),
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
_LINK_RELATION = re.compile(
    r"\b(?:link|lien\s*ket|truy\s*cap|bam|qua|tai|vao)\b",
    re.IGNORECASE,
)
_URL_TO_REQUEST = re.compile(
    r"\b(?:de|roi|va|sau\s*khi)\b[^.!?;\n]{0,40}"
    r"\b(?:nhap|dien|gui|cung\s*cap|chia\s*se)\b",
    re.IGNORECASE,
)
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
_NEGATION_BEFORE_ACTION = re.compile(
    r"\b(?:khong|dung|cho|chua)\b"
    r"(?:\s+(?:bao\s+gio|nen|can|duoc|the|dong\s+y|chap\s+nhan|"
    r"yeu\s*cau|de\s*nghi|bat\s*buoc)){0,4}"
    r"(?:\s+(?:hay|vui\s*long|phai|ban|yeu\s*cau|de\s*nghi|bat\s*buoc))*\s*$",
    re.IGNORECASE,
)
_REQUEST_CUE_BEFORE_ACTION = re.compile(
    r"\b(?:vui\s*long|hay|can|yeu\s*cau|de\s*nghi|ban\s+can|ban\s+hay)\b",
    re.IGNORECASE,
)
_PASSIVE_ACTION_BEFORE = re.compile(
    r"\b(?:da\s+)?(?:duoc|se\s+duoc)\s*$",
    re.IGNORECASE,
)
_SPEAKER_HEADER = re.compile(
    r"^\s*(?:tin\s*nhan\s+\d+\s*[-:]\s*)?"
    r"(nguoi\s+(?:gui|nhan|[a-z0-9]+)|sender|recipient)\s*:\s*(.*)$",
    re.IGNORECASE,
)
_AUTHORITY_CLAIM = re.compile(
    r"\b(?:toi|chung\s*toi|chung\s*ta|dai\s*dien)\s+"
    r"(?:la|thuoc|den\s*tu)\s+.{0,40}?"
    r"\b(?:cong\s*an|bo\s*cong\s*an|co\s*quan\s+chuc\s*nang|"
    r"toa\s*an|vien\s*kiem\s*sat|co\s*quan\s+thue|"
    r"co\s*quan\s+nha\s*nuoc)\b",
    re.IGNORECASE,
)
_TRANSFER_REQUEST = re.compile(
    r"\b(?:chuyen\s+(?:khoan\s+)?tien|chuyen\s+khoan|"
    r"nop\s+tien|gui\s+tien|nap\s+tien)\b",
    re.IGNORECASE,
)
_THREAT = re.compile(
    r"\b(?:neu\s+(?:ban\s+)?khong|khong\s+lam\s+theo\s+thi)\b"
    r"[^.!?;\n]{0,80}?\b(?:se\s+)?(?:bi\s+)?"
    r"(?:bat\s*giu|bat|phong\s*toa|khoi\s*to|giam|xu\s*ly|"
    r"khoa\s*tai\s*khoan|truy\s*to)\b|"
    r"\b(?:se|ngay\s+lap\s+tuc)\s+(?:bi\s+)?"
    r"(?:bat\s*giu|bat|phong\s*toa|khoi\s*to|giam|xu\s*ly|"
    r"khoa\s*tai\s*khoan|truy\s*to)\b",
    re.IGNORECASE,
)
_SECRECY_REQUEST = re.compile(
    r"\b(?:khong\s+duoc|dung|khong)\s+"
    r"(?:noi|bao|ke|chia\s*se|tiet\s*lo)\b"
    r"[^.!?;\n]{0,60}?\b(?:cho\s+ai|voi\s+ai|nguoi\s+than|"
    r"gia\s*dinh|bat\s*ky\s*ai)\b",
    re.IGNORECASE,
)
_EDUCATIONAL_FRAME = re.compile(
    r"\b(?:bai\s*(?:bao|viet|hoc)|vi\s*du(?:\s+minh\s*hoa)?|"
    r"huong\s*dan\s+phong\s*tranh|thu\s*doan\s+lua\s*dao|"
    r"ke\s+lua\s*dao|ke\s*gian|canh\s*bao\s+ve\s+thu\s*doan)\b",
    re.IGNORECASE,
)
_EDUCATIONAL_ADVICE = re.compile(
    r"\b(?:khong\s+lam\s+theo|dung\s+lam\s+theo|"
    r"khong\s+chuyen\s+tien|khong\s+cung\s*cap|"
    r"khong\s+chia\s*se|dung\s+bam|hay\s+xac\s*minh)\b",
    re.IGNORECASE,
)
_SAFE_MESSAGE = re.compile(
    r"\b(?:khong\s+chia\s*se\s+(?:ma\s+)?otp|"
    r"ngan\s+hang\s+khong\s+bao\s+gio\s+yeu\s+cau|"
    r"dung\s+bam\s+(?:vao\s+)?duong\s+link\s+la|"
    r"giao\s*dich\s+(?:da\s+)?thanh\s*cong|"
    r"(?:ma\s+)?otp\s+(?:cua\s+ban\s+)?(?:da\s+duoc\s+gui|da\s+duoc\s+tao)|"
    r"otp\b[^.!?;\n]{0,80}\bda\s+duoc\s+gui)\b",
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
    return _find_explicit_sensitive_request(text, context, credentials_only=True)


def _find_explicit_sensitive_request(
    text: str,
    context: str = "",
    credentials_only: bool = False,
) -> str | None:
    normalized, starts, ends = _normalize_with_offsets(text)
    normalized_context, _, _ = _normalize_with_offsets(context)
    searchable = normalized.replace("\n", " ")
    searchable_context = normalized_context.replace("\n", " ")
    sensitive_terms = _CREDENTIAL_TERMS if credentials_only else _SENSITIVE_TERMS
    sensitive_term = _CREDENTIAL_TERM if credentials_only else _SENSITIVE_TERM
    patterns = (
        tuple(
            re.compile(pattern.pattern.replace(_SENSITIVE_TERMS, sensitive_terms), re.IGNORECASE)
            for pattern in _SENSITIVE_REQUEST_PATTERNS
        )
        if credentials_only
        else _SENSITIVE_REQUEST_PATTERNS
    )

    candidates: list[re.Match[str]] = []
    for pattern in patterns:
        offset = 0
        while match := pattern.search(searchable, offset):
            candidates.append(match)
            offset = match.start() + 1
    for match in sorted(candidates, key=lambda candidate: candidate.start()):
        action_matches = list(re.finditer(rf"\b{_REQUEST_ACTIONS}\b", match.group()))
        action_match = next(iter(action_matches), None)
        if action_match is None:
            continue
        action_start = match.start() + action_match.start()
        clause_start = max(
            normalized.rfind(delimiter, 0, action_start)
            for delimiter in ".!?;\n"
        )
        action_prefix = searchable[
            max(clause_start + 1, action_start - 60) : action_start
        ]
        if _NEGATION_BEFORE_ACTION.search(
            action_prefix
        ):
            continue
        if (
            action_start > match.start()
            and not _REQUEST_CUE_BEFORE_ACTION.search(action_prefix)
            and not re.search(
                r"\b(?:cho|den)\s+toi\b",
                searchable[action_start : min(len(searchable), action_start + 40)],
            )
        ):
            continue
        if _PASSIVE_ACTION_BEFORE.search(action_prefix):
            continue
        if _SENDER_LABEL.search(normalized[clause_start + 1 : action_start]):
            continue
        context_start = (
            searchable_context.find(match.group())
            if searchable_context and searchable_context != searchable
            else match.start()
        )
        if context_start >= 0:
            context_clause_start = max(
                normalized_context.rfind(delimiter, 0, context_start)
                for delimiter in ".!?;\n"
            )
            context_action = context_start + action_match.start()
            if _NEGATION_BEFORE_ACTION.search(
                searchable_context[max(context_clause_start + 1, context_action - 60) : context_action]
            ):
                continue
            line_start = normalized_context.rfind("\n", 0, context_start) + 1
            line_end = normalized_context.find(
                "\n", context_start + len(match.group())
            )
            if line_end < 0:
                line_end = len(searchable_context)
            context_window = searchable_context[
                max(line_start, context_start - 240) : min(
                    line_end, context_start + len(match.group()) + 240
                )
            ]
            if _SAFE_EDUCATIONAL_CONTEXT.search(context_window):
                continue
        elif _SAFE_EDUCATIONAL_CONTEXT.search(normalized):
            continue

        match_end = match.end()
        while True:
            next_term = sensitive_term.search(searchable, match_end, match_end + 32)
            if next_term is None:
                break
            connector = searchable[match_end : next_term.start()]
            if not re.fullmatch(r"\s*(?:(?:,|and|va|cung|hoac)\s*)+", connector):
                break
            match_end = next_term.end()
        return _excerpt_from_normalized(text, starts, ends, match.start(), match_end)
    return None


def _message_groups(source: str) -> list[str]:
    lines = source.splitlines()
    parsed_lines: list[tuple[str | None, str]] = []
    has_speaker_labels = False
    for line in lines:
        normalized, _, _ = _normalize_with_offsets(line)
        match = _SPEAKER_HEADER.match(normalized)
        if match is None:
            parsed_lines.append((None, line))
        else:
            has_speaker_labels = True
            parsed_lines.append((match.group(1), match.group(2)))
    if not has_speaker_labels:
        return [source]

    groups: list[list[str]] = []
    current_speaker = "__unlabeled__"
    for speaker, text in parsed_lines:
        if speaker is not None and speaker != current_speaker:
            current_speaker = speaker
            groups.append([])
        elif not groups:
            groups.append([])
        groups[-1].append(text)
    return ["\n".join(lines) for lines in groups if any(lines)]


def _is_educational_context(text: str) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    return (
        _EDUCATIONAL_FRAME.search(normalized) is not None
        and _EDUCATIONAL_ADVICE.search(normalized) is not None
    )


def _original_match(text: str, pattern: re.Pattern[str]) -> str | None:
    normalized, starts, ends = _normalize_with_offsets(text)
    match = pattern.search(normalized)
    if match is None:
        return None
    return _excerpt_from_normalized(text, starts, ends, match.start(), match.end())


def _has_unnegated_match(text: str, pattern: re.Pattern[str]) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    searchable = normalized.replace("\n", " ")
    for match in pattern.finditer(searchable):
        clause_start = max(
            normalized.rfind(delimiter, 0, match.start())
            for delimiter in ".!?;\n"
        )
        prefix = searchable[max(clause_start + 1, match.start() - 60) : match.start()]
        if not _NEGATION_BEFORE_ACTION.search(prefix):
            return True
    return False


def _classify_sensitive_request(evidence: str) -> str:
    normalized, _, _ = _normalize_with_offsets(evidence)
    return (
        "PERSONAL_DATA_HARVESTING"
        if _FINANCIAL_DATA_TERMS
        and re.search(rf"\b{_FINANCIAL_DATA_TERMS}\b", normalized)
        else "CREDENTIAL_OTP_THEFT"
    )


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


def _extract_related_url(source: str, evidence: str) -> str | None:
    evidence_start = source.find(evidence)
    if evidence_start < 0:
        return None
    evidence_end = evidence_start + len(evidence)
    for match in _URL.finditer(source):
        distance = (
            match.start() - evidence_end
            if match.start() >= evidence_end
            else evidence_start - match.end()
        )
        if distance < 0 or distance > 120:
            continue
        if match.start() >= evidence_end:
            relation, _, _ = _normalize_with_offsets(
                source[evidence_end : match.start()]
            )
            related = _LINK_RELATION.search(relation) is not None
        else:
            relation, _, _ = _normalize_with_offsets(
                source[match.end() : evidence_start] + evidence
            )
            related = _URL_TO_REQUEST.search(relation) is not None
        if related:
            return match.group().rstrip(".,;:!?)]}")
    return None


def _extract_urgency(text: str) -> str | None:
    normalized, starts, ends = _normalize_with_offsets(text)
    match = _URGENCY.search(normalized)
    if match is None:
        return None
    return _excerpt_from_normalized(text, starts, ends, match.start(), match.end())


def _has_financial_organization_reference(text: str) -> bool:
    normalized, _, _ = _normalize_with_offsets(text)
    return _FINANCIAL_ORGANIZATION.search(normalized) is not None


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
    high_risk_scenarios: frozenset[str] = frozenset()
    safe_context: bool = False
    educational_context: bool = False


class EvidenceEngine:
    @staticmethod
    def is_explicit_credential_request(text: str, context: str = "") -> bool:
        return _is_explicit_credential_request(text, context)

    @staticmethod
    def is_explicit_sensitive_data_request(text: str, context: str = "") -> bool:
        return _find_explicit_sensitive_request(text, context) is not None

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
        message_groups = _message_groups(source_text)
        educational_groups = [
            group for group in message_groups if _is_educational_context(group)
        ]
        for finding in output.detected_behaviors:
            excerpt = self._find_verbatim_excerpt(source_text, finding.evidence)
            if excerpt is None:
                invalid_count += 1
                continue
            normalized_excerpt, _, _ = _normalize_with_offsets(excerpt)
            if _SAFE_MESSAGE.search(normalized_excerpt) and not _find_explicit_sensitive_request(
                excerpt, source_text
            ):
                continue
            if any(
                self._find_verbatim_excerpt(group, excerpt) is not None
                for group in educational_groups
            ):
                continue
            behavior_type = finding.type
            sensitive_request = _find_explicit_sensitive_request(
                excerpt, source_text
            )
            if sensitive_request:
                behavior_type = _classify_sensitive_request(sensitive_request)
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

        high_risk_scenarios: set[str] = set()

        def add_engine_finding(behavior_type: str, evidence: str, explanation: str) -> None:
            normalized_evidence, _, _ = _normalize_with_offsets(evidence)
            if any(
                item.type == behavior_type
                and (
                    item.evidence == evidence
                    or (
                        behavior_type
                        in {"CREDENTIAL_OTP_THEFT", "PERSONAL_DATA_HARVESTING"}
                        and normalized_evidence
                        in _normalize_with_offsets(item.evidence)[0]
                    )
                )
                for item in findings
            ):
                return
            name_vi, description = BEHAVIOR_CATALOG[behavior_type]
            finding = DetectedBehavior(
                type=behavior_type,
                name_vi=name_vi,
                description=description,
                evidence=evidence,
                explanation=explanation,
                supported_by=["evidence_engine"],
            )
            if behavior_type in {
                "CREDENTIAL_OTP_THEFT",
                "PERSONAL_DATA_HARVESTING",
            }:
                findings.insert(0, finding)
            else:
                findings.append(finding)

        for group in message_groups:
            if _is_educational_context(group):
                continue
            sensitive_evidence = _find_explicit_sensitive_request(group, group)
            if sensitive_evidence is None:
                continue
            sensitive_type = _classify_sensitive_request(sensitive_evidence)
            add_engine_finding(
                sensitive_type,
                sensitive_evidence,
                "Đoạn trích có hành động yêu cầu thông tin nhạy cảm; danh tính người gửi chưa được xác minh.",
            )
            related_context = _context_around_evidence(group, sensitive_evidence)
            url_evidence = _extract_related_url(group, sensitive_evidence)
            urgency_evidence = _extract_urgency(related_context)
            if url_evidence:
                add_engine_finding(
                    "SUSPICIOUS_WEBSITE_REDIRECTION",
                    url_evidence,
                    "Đường dẫn xuất hiện cùng yêu cầu thông tin nhạy cảm; chưa xác minh website.",
                )
            if urgency_evidence:
                add_engine_finding(
                    "URGENCY_PRESSURE",
                    urgency_evidence,
                    "Nội dung nêu thời hạn hoặc yêu cầu xử lý gấp; hậu quả thực tế chưa được xác minh.",
                )
            if url_evidence and sensitive_type in {
                "CREDENTIAL_OTP_THEFT",
                "PERSONAL_DATA_HARVESTING",
            }:
                high_risk_scenarios.add("sensitive_data_link")

        for group in message_groups:
            if _is_educational_context(group):
                continue
            authority_evidence = _original_match(group, _AUTHORITY_CLAIM)
            transfer_evidence = _original_match(group, _TRANSFER_REQUEST)
            threat_evidence = _original_match(group, _THREAT)
            secrecy_evidence = _original_match(group, _SECRECY_REQUEST)
            urgency_evidence = _extract_urgency(group)
            coercive_authority_transfer = (
                authority_evidence is not None
                and transfer_evidence is not None
                and (
                    threat_evidence is not None
                    or (
                        secrecy_evidence is not None
                        and urgency_evidence is not None
                    )
                )
            )
            if not coercive_authority_transfer:
                continue
            high_risk_scenarios.add("authority_transfer_coercion")
            add_engine_finding(
                "AUTHORITY_IMPERSONATION",
                authority_evidence,
                "Người gửi tự nhận thuộc cơ quan có thẩm quyền; danh tính chưa được xác minh.",
            )
            add_engine_finding(
                "UNUSUAL_PAYMENT_REQUEST",
                transfer_evidence,
                "Nội dung yêu cầu chuyển hoặc nộp tiền trong cùng ngữ cảnh cưỡng ép.",
            )
            if threat_evidence:
                add_engine_finding(
                    "THREATENED_CONSEQUENCES",
                    threat_evidence,
                    "Nội dung nêu hậu quả tiêu cực để gây sức ép; sự việc chưa được xác minh.",
                )
            if secrecy_evidence:
                add_engine_finding(
                    "SECRECY_REQUEST",
                    secrecy_evidence,
                    "Nội dung yêu cầu không chia sẻ hoặc xác minh với người khác.",
                )
            if urgency_evidence:
                add_engine_finding(
                    "URGENCY_PRESSURE",
                    urgency_evidence,
                    "Nội dung tạo áp lực thời gian trong cùng ngữ cảnh yêu cầu chuyển tiền.",
                )

        for group in message_groups:
            group_types = {
                finding.type
                for finding in findings
                if self._find_verbatim_excerpt(group, finding.evidence) is not None
            }
            if (
                "AUTHORITY_IMPERSONATION" in group_types
                and "UNUSUAL_PAYMENT_REQUEST" in group_types
                and (
                    "THREATENED_CONSEQUENCES" in group_types
                    or (
                        "SECRECY_REQUEST" in group_types
                        and "URGENCY_PRESSURE" in group_types
                    )
                )
            ):
                high_risk_scenarios.add("authority_transfer_coercion")

        normalized_source, _, _ = _normalize_with_offsets(source_text)
        safe_context = (
            _SAFE_MESSAGE.search(normalized_source) is not None
            and not any(
                _find_explicit_sensitive_request(group, group) is not None
                for group in message_groups
            )
            and not any(
                not _is_educational_context(group)
                and (
                    _has_unnegated_match(group, _TRANSFER_REQUEST)
                    or _THREAT.search(
                        _normalize_with_offsets(group)[0]
                    )
                )
                for group in message_groups
            )
        )
        return EvidenceAssessment(
            findings,
            invalid_count,
            frozenset(high_risk_scenarios),
            safe_context,
            bool(message_groups) and len(educational_groups) == len(message_groups),
        )

    @staticmethod
    def has_explicit_credential_request(text: str) -> bool:
        return _find_explicit_credential_request(text, text) is not None

    @staticmethod
    def extract_url(text: str) -> str | None:
        return _extract_url(text)

    @staticmethod
    def related_context(source: str, evidence: str) -> str:
        for group in _message_groups(source):
            if EvidenceEngine._find_verbatim_excerpt(group, evidence) is not None:
                return _context_around_evidence(group, evidence)
        return source

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