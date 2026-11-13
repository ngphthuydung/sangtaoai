import { useRef, useState } from 'react';
import {
  MAX_AUDIO_SIZE_BYTES,
  MAX_IMAGE_SIZE_BYTES,
  MAX_MEDIA_FILES_PER_BATCH,
  runSequentially,
  validateMediaFile,
} from './mediaBatch';

type InputMode = 'text' | 'url' | 'image' | 'audio';
type Screen = 'home' | 'result' | 'menu' | 'information';
type RiskLevel = 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'INSUFFICIENT_DATA';

interface DetectedBehavior {
  name_vi: string;
  description: string;
  evidence: string;
  explanation: string;
}

interface AnalysisResult {
  risk_level: RiskLevel;
  summary: string;
  detected_behaviors: DetectedBehavior[];
  recommendations: string[];
  unverified_information: string[];
  limitations: string[];
  analysis_status?: string;
  analysis_failure_reason?: string | null;
  analysis_method?: string;
  transcription_status?: 'COMPLETED' | 'PARTIAL' | 'FAILED' | null;
}

interface RequestMetadata {
  requestId?: string;
  stage?: string;
  errorCategory?: string;
  httpStatus?: number;
  providerStatus?: number;
  durationMs?: number;
  retryCount?: number;
}

type MediaStatus = 'pending' | 'processing' | 'completed' | 'failed' | 'invalid';

interface MediaBatchItem {
  id: string;
  file: File;
  status: MediaStatus;
  mimeType?: string;
  result?: AnalysisResult;
  error?: string;
  diagnostics?: RequestMetadata;
}

interface URLCheckResponse {
  url: string;
  status: string;
  risk_level: string;
  message: string;
}

type InformationTopic = 'about' | 'instructions' | 'privacy' | 'technical' | 'settings';

const riskPresentation: Record<
  RiskLevel,
  { icon: string; label: string; className: string }
> = {
  HIGH_RISK: { icon: '!', label: 'Nguy cơ cao', className: 'risk-high' },
  SUSPICIOUS: {
    icon: '?',
    label: 'Có dấu hiệu đáng ngờ',
    className: 'risk-suspicious',
  },
  LOW_RISK: {
    icon: '✓',
    label: 'Chưa thấy dấu hiệu rõ ràng',
    className: 'risk-low',
  },
  INSUFFICIENT_DATA: {
    icon: 'i',
    label: 'Chưa đủ bằng chứng',
    className: 'risk-unknown',
  },
};

const inputOptions: { id: InputMode; icon: string; label: string }[] = [
  { id: 'text', icon: '✉', label: 'Tin nhắn' },
  { id: 'url', icon: '↗', label: 'Đường link' },
  { id: 'image', icon: '▧', label: 'Hình ảnh' },
  { id: 'audio', icon: '♫', label: 'Âm thanh' },
];

const informationContent: Record<
  InformationTopic,
  { title: string; paragraphs: string[] }
> = {
  about: {
    title: 'Giới thiệu',
    paragraphs: [
      'Lá Chắn Người Thân giúp nhận biết một số dấu hiệu đáng chú ý trong tin nhắn, đường link, hình ảnh và âm thanh.',
      'Kết quả chỉ mang tính tham khảo, không xác minh danh tính người gửi và không bảo đảm nội dung an toàn.',
    ],
  },
  instructions: {
    title: 'Hướng dẫn sử dụng',
    paragraphs: [
      'Chọn một loại nội dung, nhập hoặc chọn nội dung cần kiểm tra rồi nhấn “Kiểm tra”.',
      'Nếu kết quả chưa đủ thông tin hoặc dịch vụ gặp sự cố, hãy giữ nguyên nội dung và thử lại. Không chuyển tiền hay chia sẻ mật khẩu, mã OTP khi chưa xác minh.',
    ],
  },
  privacy: {
    title: 'Quyền riêng tư',
    paragraphs: [
      'Tin nhắn, hình ảnh và âm thanh chỉ được gửi để phân tích khi bạn đánh dấu đồng ý. Đường link được gửi tới máy chủ để kiểm tra cơ bản.',
      'Không gửi thông tin nhạy cảm nếu không cần thiết. Nội dung được xử lý bởi dịch vụ AI bên ngoài; ứng dụng không cam kết lưu trữ hoặc xóa dữ liệu tại nhà cung cấp.',
    ],
  },
  technical: {
    title: 'Thông tin kỹ thuật',
    paragraphs: [
      'Ứng dụng gửi yêu cầu tới máy chủ Lá Chắn Người Thân. Máy chủ mới kết nối dịch vụ AI sau khi có sự đồng ý.',
      'Nếu máy chủ hoặc dịch vụ AI tạm thời không phản hồi, ứng dụng không đưa ra kết luận. Nội dung bạn nhập vẫn còn trên màn hình để thử lại.',
    ],
  },
  settings: {
    title: 'Cài đặt',
    paragraphs: [
      'Mục cài đặt hiện chưa có tùy chọn bổ sung. Bạn cần đồng ý mỗi lần gửi tin nhắn, hình ảnh hoặc âm thanh để phân tích.',
      'Cách xử lý dữ liệu không thay đổi tại mục này.',
    ],
  },
};

const feedbackUrl = getFeedbackUrl();

function isValidHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === 'http:' || url.protocol === 'https:') && Boolean(url.hostname);
  } catch {
    return false;
  }
}

function getFeedbackUrl(): string | null {
  const configuredUrl = import.meta.env.VITE_FEEDBACK_URL?.trim();
  if (!configuredUrl) return null;
  try {
    const url = new URL(configuredUrl);
    return url.protocol === 'https:' && url.hostname ? url.toString() : null;
  } catch {
    return null;
  }
}

class RequestFailure extends Error {
  readonly canRetry: boolean;
  readonly diagnostics?: RequestMetadata;

  constructor(
    message: string,
    canRetry: boolean,
    diagnostics?: RequestMetadata,
  ) {
    super(message);
    this.name = 'RequestFailure';
    this.canRetry = canRetry;
    this.diagnostics = diagnostics;
  }
}

function getResponseMetadata(response: Response): RequestMetadata {
  const getNumber = (name: string) => {
    const value = response.headers.get(name);
    if (!value) return undefined;
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  };
  return {
    requestId: response.headers.get('x-request-id') ?? undefined,
    stage: response.headers.get('x-processing-stage') ?? undefined,
    errorCategory: response.headers.get('x-error-category') ?? undefined,
    httpStatus: response.status,
    providerStatus: getNumber('x-provider-status'),
    durationMs: getNumber('x-processing-duration-ms'),
    retryCount: getNumber('x-ai-retry-count'),
  };
}

async function getApiError(response: Response, fallback: string): Promise<string> {
  try {
    const body: { detail?: unknown } = await response.json();
    if (typeof body.detail === 'string' && body.detail.trim()) return body.detail;
  } catch {
    // Non-JSON responses use a safe fallback.
  }
  return `${fallback} (HTTP ${response.status}).`;
}

async function requestApi(url: string, init: RequestInit): Promise<Response> {
  const request = async () => {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 70_000);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new RequestFailure(
          'Máy chủ phản hồi quá chậm. Nội dung vẫn được giữ lại; bạn có thể thử lại.',
          true,
        );
      }
      if (error instanceof TypeError) {
        throw new RequestFailure(
          'Không thể kết nối với máy chủ. Hãy kiểm tra mạng rồi thử lại.',
          true,
        );
      }
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  };

  return request();
}

function parseAnalysisResult(payload: unknown): AnalysisResult {
  if (typeof payload !== 'object' || payload === null) {
    throw new RequestFailure(
      'Không đọc được kết quả. Nội dung vẫn được giữ lại để thử lại.',
      true,
    );
  }
  const data = payload as Record<string, unknown>;
  const riskLevels = new Set<RiskLevel>([
    'LOW_RISK',
    'SUSPICIOUS',
    'HIGH_RISK',
    'INSUFFICIENT_DATA',
  ]);
  if (
    typeof data.risk_level !== 'string' ||
    !riskLevels.has(data.risk_level as RiskLevel) ||
    typeof data.summary !== 'string' ||
    !Array.isArray(data.detected_behaviors) ||
    !Array.isArray(data.recommendations) ||
    (data.analysis_status !== undefined &&
      !['COMPLETED', 'NOT_ANALYZED', 'FAILED'].includes(String(data.analysis_status))) ||
    (data.transcription_status !== undefined &&
      data.transcription_status !== null &&
      !['COMPLETED', 'PARTIAL', 'FAILED'].includes(String(data.transcription_status)))
  ) {
    throw new RequestFailure(
      'Máy chủ trả về kết quả không đúng định dạng. Nội dung vẫn được giữ lại để thử lại.',
      true,
    );
  }

  const findings = data.detected_behaviors.map((item): DetectedBehavior => {
    if (typeof item !== 'object' || item === null) {
      throw new RequestFailure('Máy chủ trả về kết quả không đúng định dạng.', true);
    }
    const finding = item as Record<string, unknown>;
    if (
      typeof finding.name_vi !== 'string' ||
      typeof finding.description !== 'string' ||
      typeof finding.evidence !== 'string' ||
      typeof finding.explanation !== 'string'
    ) {
      throw new RequestFailure('Máy chủ trả về kết quả không đúng định dạng.', true);
    }
    return {
      name_vi: finding.name_vi,
      description: finding.description,
      evidence: finding.evidence,
      explanation: finding.explanation,
    };
  });

  if (!data.recommendations.every((item) => typeof item === 'string')) {
    throw new RequestFailure('Máy chủ trả về kết quả không đúng định dạng.', true);
  }
  const getStringList = (key: 'unverified_information' | 'limitations') => {
    const value = data[key];
    if (value === undefined) return [];
    if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
      throw new RequestFailure('Máy chủ trả về kết quả không đúng định dạng.', true);
    }
    return value as string[];
  };

  return {
    risk_level: data.risk_level as RiskLevel,
    summary: data.summary,
    detected_behaviors: findings,
    recommendations: data.recommendations as string[],
    unverified_information: getStringList('unverified_information'),
    limitations: getStringList('limitations'),
    analysis_status:
      typeof data.analysis_status === 'string' ? data.analysis_status : 'COMPLETED',
    analysis_failure_reason:
      typeof data.analysis_failure_reason === 'string'
        ? data.analysis_failure_reason
        : null,
    analysis_method:
      typeof data.analysis_method === 'string' ? data.analysis_method : undefined,
    transcription_status:
      typeof data.transcription_status === 'string'
        ? (data.transcription_status as AnalysisResult['transcription_status'])
        : null,
  };
}

async function readAnalysisResult(response: Response): Promise<AnalysisResult> {
  try {
    return parseAnalysisResult(await response.json());
  } catch (error) {
    if (error instanceof RequestFailure) throw error;
    throw new RequestFailure(
      'Không đọc được kết quả từ máy chủ. Nội dung vẫn được giữ lại để thử lại.',
      true,
    );
  }
}

function assertAnalysisCompleted(result: AnalysisResult): void {
  if (
    result.analysis_status === 'FAILED' ||
    result.analysis_method === 'LLM_UNAVAILABLE' ||
    result.analysis_method === 'LLM_NOT_CONFIGURED'
  ) {
    throw new RequestFailure(
      'Dịch vụ phân tích đang gặp sự cố. Đây không phải kết luận an toàn; nội dung vẫn được giữ lại.',
      true,
    );
  }
  if (result.analysis_status === 'NOT_ANALYZED') {
    throw new RequestFailure(
      'Nội dung chưa được phân tích. Vui lòng kiểm tra sự đồng ý và thử lại.',
      false,
    );
  }
}

function getInputLabel(mode: InputMode): string {
  return inputOptions.find((option) => option.id === mode)?.label ?? 'nội dung';
}

export default function App() {
  const [mode, setMode] = useState<InputMode>('text');
  const [screen, setScreen] = useState<Screen>('home');
  const [topic, setTopic] = useState<InformationTopic>('about');
  const [message, setMessage] = useState('');
  const [url, setUrl] = useState('');
  const [imageBatch, setImageBatch] = useState<MediaBatchItem[]>([]);
  const [audioBatch, setAudioBatch] = useState<MediaBatchItem[]>([]);
  const [context, setContext] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [canRetry, setCanRetry] = useState(false);
  const [requestDiagnostics, setRequestDiagnostics] = useState<RequestMetadata>();
  const [selectionNotice, setSelectionNotice] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const requestInFlight = useRef(false);
  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? '';
  const currentBatch = mode === 'image' ? imageBatch : audioBatch;

  function updateMediaItem(
    kind: 'image' | 'audio',
    id: string,
    update: Partial<MediaBatchItem>,
  ) {
    const setBatch = kind === 'image' ? setImageBatch : setAudioBatch;
    setBatch((items) =>
      items.map((item) => (item.id === id ? { ...item, ...update } : item)),
    );
  }

  function clearRequestMessage() {
    setError(null);
    setCanRetry(false);
    setRequestDiagnostics(undefined);
    setResult(null);
  }

  function chooseMode(nextMode: InputMode) {
    if (loading) return;
    setMode(nextMode);
    clearRequestMessage();
    setSelectionNotice('');
    setConsent(false);
  }

  async function chooseMediaFiles(fileList: FileList | null, kind: 'image' | 'audio') {
    if (!fileList?.length) return;
    clearRequestMessage();
    const setBatch = kind === 'image' ? setImageBatch : setAudioBatch;
    const files = Array.from(fileList);
    const selected = files.slice(0, MAX_MEDIA_FILES_PER_BATCH);
    const batch = await Promise.all(
      selected.map(async (file, index): Promise<MediaBatchItem> => {
        const item: MediaBatchItem = {
          id: `${file.name}-${file.size}-${file.lastModified}-${index}`,
          file,
          status: 'pending',
        };
        try {
          item.mimeType = await validateMediaFile(file, kind);
        } catch (validationError) {
          item.status = 'invalid';
          item.error =
            validationError instanceof Error
              ? validationError.message
              : 'Tệp không hợp lệ.';
        }
        return item;
      }),
    );
    setBatch(batch);
    setSelectionNotice(
      files.length > MAX_MEDIA_FILES_PER_BATCH
        ? `Đã chọn ${MAX_MEDIA_FILES_PER_BATCH} tệp đầu tiên. Mỗi lần chỉ kiểm tra tối đa ${MAX_MEDIA_FILES_PER_BATCH} tệp.`
        : '',
    );
  }

  async function analyzeMediaFile(kind: 'image' | 'audio', item: MediaBatchItem) {
    updateMediaItem(kind, item.id, { status: 'processing', error: undefined });
    const route = kind === 'image' ? 'image' : 'audio';
    try {
      const response = await requestApi(
        `${apiBaseUrl}/api/v1/scam-analysis/${route}?allow_external_processing=true`,
        {
          method: 'POST',
          headers: { 'Content-Type': item.mimeType ?? '' },
          body: item.file,
        },
      );
      const diagnostics = getResponseMetadata(response);
      if (!response.ok) {
        const message =
          response.status >= 500
            ? 'Dịch vụ phân tích đang gặp sự cố. Đây không phải kết luận an toàn.'
            : await getApiError(response, 'Chưa thể phân tích tệp này');
        throw new RequestFailure(message, response.status >= 500, diagnostics);
      }

      let analysis: AnalysisResult;
      try {
        analysis = await readAnalysisResult(response);
        assertAnalysisCompleted(analysis);
      } catch (error) {
        throw new RequestFailure(
          error instanceof Error ? error.message : 'Không đọc được kết quả.',
          error instanceof RequestFailure && error.canRetry,
          diagnostics,
        );
      }
      updateMediaItem(kind, item.id, {
        status: 'completed',
        result: analysis,
        diagnostics,
      });
    } catch (error) {
      const failure =
        error instanceof RequestFailure
          ? error
          : new RequestFailure('Không thể kết nối để phân tích tệp này.', true);
      updateMediaItem(kind, item.id, {
        status: failure.canRetry ? 'failed' : 'invalid',
        error: failure.message,
        diagnostics: failure.diagnostics,
      });
    }
  }

  async function analyzeMediaBatch(kind: 'image' | 'audio') {
    if (requestInFlight.current) return;
    const batch = kind === 'image' ? imageBatch : audioBatch;
    const toProcess = batch.filter(
      (item) => item.status === 'pending' || item.status === 'failed',
    );
    if (toProcess.length === 0) {
      setError('Không có tệp sẵn sàng để kiểm tra. Hãy xem lại danh sách đã chọn.');
      return;
    }

    requestInFlight.current = true;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      await runSequentially(toProcess, (item) => analyzeMediaFile(kind, item));
      setScreen('result');
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  async function retryMediaFile(kind: 'image' | 'audio', id: string) {
    if (requestInFlight.current) return;
    const batch = kind === 'image' ? imageBatch : audioBatch;
    const item = batch.find((entry) => entry.id === id);
    if (!item || item.status !== 'failed') return;

    requestInFlight.current = true;
    setLoading(true);
    try {
      await analyzeMediaFile(kind, item);
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  async function analyze() {
    if (requestInFlight.current) return;

    const content = message.trim();
    const targetUrl = url.trim();
    const isMedia = mode === 'image' || mode === 'audio';
    if (mode === 'text' && !content) {
      setError('Vui lòng nhập tin nhắn hoặc nội dung cần kiểm tra.');
      return;
    }
    if (mode === 'url' && !targetUrl) {
      setError('Vui lòng dán đường link cần kiểm tra.');
      return;
    }
    if (mode === 'url' && !isValidHttpUrl(targetUrl)) {
      setError('Đường link cần bắt đầu bằng http:// hoặc https:// và có tên miền hợp lệ.');
      return;
    }
    if (isMedia && currentBatch.length === 0) {
      setError(`Vui lòng chọn ${mode === 'image' ? 'ảnh' : 'tệp âm thanh'} cần kiểm tra.`);
      return;
    }
    if (mode !== 'url' && !consent) {
      setError(`Vui lòng đồng ý trước khi gửi ${getInputLabel(mode).toLowerCase()} đến dịch vụ AI.`);
      return;
    }
    if (isMedia) {
      await analyzeMediaBatch(mode);
      return;
    }

    requestInFlight.current = true;
    setLoading(true);
    setError(null);
    setCanRetry(false);
    setRequestDiagnostics(undefined);
    setResult(null);

    let responseDiagnostics: RequestMetadata | undefined;
    try {
      let response: Response;
      if (mode === 'url') {
        response = await requestApi(`${apiBaseUrl}/api/v1/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
        });
      } else {
        response = await requestApi(`${apiBaseUrl}/api/v1/scam-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content,
            context: context.trim() || null,
            allow_external_processing: true,
          }),
        });
      }

      responseDiagnostics = getResponseMetadata(response);
      if (!response.ok) {
        const responseMessage =
          response.status >= 500
            ? 'Dịch vụ chưa thể xử lý yêu cầu. Đây không phải kết luận an toàn.'
            : await getApiError(response, 'Chưa thể kiểm tra nội dung');
        const requestCode = responseDiagnostics.requestId
          ? ` Mã hỗ trợ: ${responseDiagnostics.requestId}.`
          : '';
        throw new RequestFailure(
          responseMessage + requestCode,
          response.status >= 500,
          responseDiagnostics,
        );
      }

      if (mode === 'url') {
        let data: URLCheckResponse;
        try {
          const payload: unknown = await response.json();
          if (
            typeof payload !== 'object' ||
            payload === null ||
            !('url' in payload) ||
            typeof payload.url !== 'string' ||
            !('risk_level' in payload) ||
            typeof payload.risk_level !== 'string' ||
            !('message' in payload) ||
            typeof payload.message !== 'string' ||
            !('status' in payload) ||
            typeof payload.status !== 'string'
          ) {
            throw new Error('invalid response');
          }
          data = payload as URLCheckResponse;
        } catch {
          throw new RequestFailure('Không đọc được kết quả kiểm tra đường link.', true);
        }
        const needsReview = data.risk_level === 'needs_review';
        setResult({
          risk_level: needsReview ? 'SUSPICIOUS' : 'INSUFFICIENT_DATA',
          summary: data.message,
          detected_behaviors: [],
          recommendations: [
            needsReview
              ? 'Không mở liên kết hoặc nhập thông tin cá nhân, mật khẩu hay mã OTP.'
              : 'Chưa thể xác nhận đường link an toàn. Hãy xác minh qua kênh chính thức trước khi mở.',
          ],
          unverified_information: [
            'Hệ thống không truy cập trang web và không xác minh danh tính chủ sở hữu tên miền.',
          ],
          limitations: [
            'Đây là kiểm tra sơ bộ dựa trên địa chỉ đường link; chưa kiểm tra nội dung trang hoặc danh tiếng tên miền.',
            'Không có dấu hiệu được phát hiện không đồng nghĩa đường link an toàn.',
          ],
        });
      } else {
        const analysis = await readAnalysisResult(response);
        assertAnalysisCompleted(analysis);
        setResult(analysis);
      }
      setScreen('result');
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Đã xảy ra lỗi không xác định. Vui lòng thử lại.',
      );
      setCanRetry(requestError instanceof RequestFailure && requestError.canRetry);
      setRequestDiagnostics(
        requestError instanceof RequestFailure && requestError.diagnostics
          ? requestError.diagnostics
          : responseDiagnostics,
      );
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  function openInformation(nextTopic: InformationTopic) {
    setTopic(nextTopic);
    setScreen('information');
  }

  const presentation = result ? riskPresentation[result.risk_level] : null;
  const completedMedia = currentBatch.filter(
    (item): item is MediaBatchItem & { result: AnalysisResult } =>
      item.status === 'completed' && item.result !== undefined,
  );
  const unprocessedMedia = currentBatch.filter(
    (item) => item.status === 'failed' || item.status === 'invalid' || item.status === 'pending',
  );
  const combinedRisk: RiskLevel | null =
    completedMedia.length === 0
      ? null
      : completedMedia.some((item) => item.result.risk_level === 'HIGH_RISK')
      ? 'HIGH_RISK'
      : completedMedia.some((item) => item.result.risk_level === 'SUSPICIOUS')
        ? 'SUSPICIOUS'
        : completedMedia.some((item) => item.result.risk_level === 'INSUFFICIENT_DATA') ||
            unprocessedMedia.length > 0
          ? 'INSUFFICIENT_DATA'
          : completedMedia.length > 0
            ? 'LOW_RISK'
            : null;
  const combinedPresentation = combinedRisk ? riskPresentation[combinedRisk] : null;
  const allMediaFailed = completedMedia.length === 0 && currentBatch.some(
    (item) => item.status === 'failed',
  );
  const combinedRecommendation =
    unprocessedMedia.length > 0
      ? `${completedMedia.some((item) => item.result.risk_level === 'HIGH_RISK')
          ? 'Có tệp có nguy cơ cao. Không cung cấp mã OTP, mật khẩu hoặc tiền.'
          : 'Chưa thể kết luận cho toàn bộ nội dung.'} Còn ${unprocessedMedia.length} tệp chưa kiểm tra; hãy xem danh sách và thử lại từng tệp.`
      : completedMedia
          .slice()
          .sort((left, right) => {
            const priority: Record<RiskLevel, number> = {
              HIGH_RISK: 0,
              SUSPICIOUS: 1,
              INSUFFICIENT_DATA: 2,
              LOW_RISK: 3,
            };
            return priority[left.result.risk_level] - priority[right.result.risk_level];
          })[0]?.result.recommendations[0] ??
        'Hãy xác minh qua kênh chính thức trước khi hành động.';
  const singleRecommendation =
    result?.risk_level === 'LOW_RISK'
      ? `${result.recommendations[0] ?? 'Chưa thấy dấu hiệu rõ ràng.'} Kết quả này không xác nhận an toàn.`
      : result?.recommendations[0] ??
        'Hãy xác minh qua kênh chính thức trước khi hành động.';
  const safeCombinedRecommendation =
    combinedRisk === 'LOW_RISK'
      ? `${combinedRecommendation} Kết quả này không xác nhận an toàn.`
      : combinedRecommendation;
  const strongestMediaSummary = completedMedia
    .slice()
    .sort((left, right) => {
      const priority: Record<RiskLevel, number> = {
        HIGH_RISK: 0,
        SUSPICIOUS: 1,
        INSUFFICIENT_DATA: 2,
        LOW_RISK: 3,
      };
      return priority[left.result.risk_level] - priority[right.result.risk_level];
    })[0]?.result.summary;
  const combinedSummary =
    unprocessedMedia.length > 0
      ? `${strongestMediaSummary ?? 'Chưa có tệp nào được phân tích.'} ${
          unprocessedMedia.length
        } tệp chưa được kiểm tra; kết quả chưa bao quát toàn bộ nội dung.`
      : strongestMediaSummary ??
        (allMediaFailed
          ? 'Dịch vụ chưa thể phân tích các tệp này. Đây không phải kết luận an toàn.'
          : 'Chưa có tệp nào được phân tích.');

  return (
    <div className="app-shell">
      <header className="site-header">
        <a
          className="brand"
          href="#main"
          onClick={(event) => {
            event.preventDefault();
            setScreen('home');
          }}
          aria-label="Lá Chắn Người Thân"
        >
          <span className="brand-mark" aria-hidden="true">✓</span>
          <span className="brand-name">Lá Chắn Người Thân</span>
        </a>
        <button
          className="menu-button"
          type="button"
          onClick={() => setScreen(screen === 'menu' ? 'home' : 'menu')}
          aria-label={screen === 'menu' ? 'Đóng menu' : 'Mở menu'}
        >
          <span aria-hidden="true">{screen === 'menu' ? '×' : '☰'}</span>
          <span>{screen === 'menu' ? 'Đóng' : 'Menu'}</span>
        </button>
      </header>

      <main id="main" className="main-content">
        {screen === 'home' && (
          <section className="workspace-card" aria-labelledby="page-title">
            <h1 id="page-title">Bạn muốn kiểm tra điều gì?</h1>
            <div className="mode-grid" role="group" aria-label="Chọn loại nội dung">
              {inputOptions.map((option) => (
                <button
                  key={option.id}
                  type="button"
                  aria-pressed={mode === option.id}
                  onClick={() => chooseMode(option.id)}
                  disabled={loading}
                  className={`mode-card ${mode === option.id ? 'mode-card-active' : ''}`}
                >
                  <span className="mode-icon" aria-hidden="true">{option.icon}</span>
                  <span>{option.label}</span>
                  {mode === option.id && <span className="mode-selected">Đang chọn</span>}
                </button>
              ))}
            </div>

            <div className="input-panel">
              {mode === 'text' && (
                <>
                  <label htmlFor="message" className="field-label">Tin nhắn cần kiểm tra</label>
                  <textarea
                    id="message"
                    value={message}
                    onChange={(event) => {
                      setMessage(event.target.value);
                      clearRequestMessage();
                    }}
                    maxLength={12000}
                    rows={6}
                    className="text-input"
                    placeholder="Dán tin nhắn vào đây"
                  />
                  <details className="context-details">
                    <summary>Thêm bối cảnh (không bắt buộc)</summary>
                    <label htmlFor="context" className="field-label">Thông tin về người gửi hoặc tình huống</label>
                    <textarea
                      id="context"
                      value={context}
                      onChange={(event) => {
                        setContext(event.target.value);
                        clearRequestMessage();
                      }}
                      maxLength={4000}
                      rows={3}
                      className="text-input context-input"
                    />
                  </details>
                </>
              )}
              {mode === 'url' && (
                <>
                  <label htmlFor="url" className="field-label">Đường link cần kiểm tra</label>
                  <input
                    id="url"
                    type="url"
                    inputMode="url"
                    autoCapitalize="none"
                    autoComplete="url"
                    spellCheck={false}
                    value={url}
                    onChange={(event) => {
                      setUrl(event.target.value);
                      clearRequestMessage();
                    }}
                    className="text-input single-line-input"
                    placeholder="https://"
                  />
                </>
              )}
              {mode === 'image' && (
                <>
                  <label htmlFor="image-upload" className="field-label">Chọn hình ảnh</label>
                  <p id="image-help" className="field-help">
                    JPG, PNG hoặc WEBP · tối đa {MAX_MEDIA_FILES_PER_BATCH} ảnh, mỗi ảnh{' '}
                    {MAX_IMAGE_SIZE_BYTES / (1024 * 1024)} MiB
                  </p>
                  {selectionNotice && <p className="field-help" role="status">{selectionNotice}</p>}
                  <input
                    id="image-upload"
                    type="file"
                    accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp"
                    multiple
                    aria-describedby="image-help"
                    onChange={(event) => {
                      void chooseMediaFiles(event.currentTarget.files, 'image');
                      event.currentTarget.value = '';
                    }}
                    className="file-input"
                  />
                  {mode === 'image' && currentBatch.length > 0 && (
                    <ul className="media-list" aria-label="Danh sách ảnh đã chọn" aria-live="polite">
                      {currentBatch.map((item) => (
                        <li className="media-item" key={item.id}>
                          <span className="media-file-name">{item.file.name}</span>
                          <span className={`media-status media-status-${item.status}`}>
                            {item.status === 'pending' && 'Chờ kiểm tra'}
                            {item.status === 'processing' && 'Đang kiểm tra'}
                            {item.status === 'completed' && 'Đã kiểm tra'}
                            {item.status === 'failed' && 'Chưa kiểm tra được'}
                            {item.status === 'invalid' && 'Tệp không hợp lệ'}
                          </span>
                          {item.error && <span className="media-error">{item.error}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
              {mode === 'audio' && (
                <>
                  <label htmlFor="audio-upload" className="field-label">Chọn tệp âm thanh</label>
                  <p id="audio-help" className="field-help">
                    MP3, WAV hoặc M4A · tối đa {MAX_MEDIA_FILES_PER_BATCH} tệp, mỗi tệp{' '}
                    {MAX_AUDIO_SIZE_BYTES / (1024 * 1024)} MiB
                  </p>
                  {selectionNotice && <p className="field-help" role="status">{selectionNotice}</p>}
                  <input
                    id="audio-upload"
                    type="file"
                    accept=".mp3,audio/mpeg,.wav,audio/wav,.m4a,audio/mp4"
                    multiple
                    aria-describedby="audio-help"
                    onChange={(event) => {
                      void chooseMediaFiles(event.currentTarget.files, 'audio');
                      event.currentTarget.value = '';
                    }}
                    className="file-input"
                  />
                  {mode === 'audio' && currentBatch.length > 0 && (
                    <ul className="media-list" aria-label="Danh sách âm thanh đã chọn" aria-live="polite">
                      {currentBatch.map((item) => (
                        <li className="media-item" key={item.id}>
                          <span className="media-file-name">{item.file.name}</span>
                          <span className={`media-status media-status-${item.status}`}>
                            {item.status === 'pending' && 'Chờ kiểm tra'}
                            {item.status === 'processing' && 'Đang kiểm tra'}
                            {item.status === 'completed' && 'Đã kiểm tra'}
                            {item.status === 'failed' && 'Chưa kiểm tra được'}
                            {item.status === 'invalid' && 'Tệp không hợp lệ'}
                          </span>
                          {item.error && <span className="media-error">{item.error}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              )}
            </div>

            {mode !== 'url' && (
              <label className="consent-box">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                />
                <span>Tôi đồng ý gửi nội dung này tới dịch vụ AI để phân tích.</span>
              </label>
            )}

            {error && (
              <div className="error-message" role="alert">
                <span>{error}</span>
                {requestDiagnostics && (
                  <p className="diagnostic-note">
                    {requestDiagnostics.requestId && `Mã hỗ trợ: ${requestDiagnostics.requestId}`}
                    {requestDiagnostics.httpStatus !== undefined &&
                      ` · HTTP ${requestDiagnostics.httpStatus}`}
                    {requestDiagnostics.providerStatus !== undefined &&
                      ` · Nhà cung cấp ${requestDiagnostics.providerStatus}`}
                    {requestDiagnostics.stage && ` · Giai đoạn ${requestDiagnostics.stage}`}
                    {requestDiagnostics.errorCategory &&
                      ` · Loại lỗi ${requestDiagnostics.errorCategory}`}
                    {requestDiagnostics.durationMs !== undefined &&
                      ` · ${requestDiagnostics.durationMs} ms`}
                    {requestDiagnostics.retryCount !== undefined &&
                      ` · Đã thử lại ${requestDiagnostics.retryCount} lần`}
                  </p>
                )}
                {canRetry && (
                  <button
                    className="retry-button"
                    type="button"
                    onClick={() => void analyze()}
                    disabled={loading}
                  >
                    Thử lại
                  </button>
                )}
              </div>
            )}

            {loading && (
              <p className="loading-message" role="status" aria-live="polite">
                <span className="loading-spinner" aria-hidden="true" />
                Đang kiểm tra. Vui lòng chờ…
              </p>
            )}

            <button
              type="button"
              onClick={() => void analyze()}
              disabled={
                loading ||
                (mode === 'text' && (!message.trim() || !consent)) ||
                (mode === 'url' && !url.trim()) ||
                (mode === 'image' &&
                  (!currentBatch.some((item) => item.status === 'pending' || item.status === 'failed') ||
                    !consent)) ||
                (mode === 'audio' &&
                  (!currentBatch.some((item) => item.status === 'pending' || item.status === 'failed') ||
                    !consent))
              }
              className="primary-button"
            >
              {loading ? 'Đang kiểm tra…' : 'Kiểm tra'}
            </button>
          </section>
        )}

        {screen === 'result' && result && presentation && (
          <section className="report-card" aria-labelledby="report-title" aria-live="polite">
            <button
              type="button"
              className="back-button"
              onClick={() => {
                setScreen('home');
                setResult(null);
              }}
            >
              ← Quay lại nội dung
            </button>
            <h2 className="report-section-heading">Mức độ an toàn</h2>
            <div className={`report-status ${presentation.className}`}>
              <span className="risk-icon" aria-hidden="true">{presentation.icon}</span>
              <h1 id="report-title">{presentation.label}</h1>
            </div>
            <p className="report-summary">{result.summary}</p>
            <div className="report-body">
              <section className="next-action">
                <h2>Bạn nên làm gì?</h2>
                <p>
                  {singleRecommendation}
                </p>
              </section>
              <details className="report-details">
                <summary>Xem giải thích chi tiết</summary>
                <section className="report-section">
                  <h2>Mức độ bằng chứng</h2>
                  <p>Đoạn trích có thể đã ẩn thông tin riêng tư.</p>
                  <p>
                    {result.detected_behaviors.length > 0
                      ? `Có ${result.detected_behaviors.length} trích dẫn khớp với nội dung đã gửi.`
                      : 'Chưa có trích dẫn cụ thể khớp với nội dung đã gửi.'}
                  </p>
                  {result.transcription_status && (
                    <p>
                      Bản ghi âm:{' '}
                      {result.transcription_status === 'COMPLETED' && 'đã nghe rõ lời nói chính.'}
                      {result.transcription_status === 'PARTIAL' && 'chỉ nghe rõ một phần.'}
                      {result.transcription_status === 'FAILED' && 'không nghe rõ lời nói.'}
                    </p>
                  )}
                </section>
                {result.recommendations.length > 1 && (
                  <section className="report-section">
                    <h2>Các bước tiếp theo</h2>
                    <ul>
                      {result.recommendations.slice(1).map((item, index) => (
                        <li key={`${item}-${index}`}>{item}</li>
                      ))}
                    </ul>
                  </section>
                )}
                <section className="report-section">
                  <h2>Dấu hiệu đáng ngờ</h2>
                  {result.detected_behaviors.length > 0 ? (
                    <ul className="finding-list">
                      {result.detected_behaviors.map((behavior, index) => (
                        <li className="finding-card" key={`${behavior.name_vi}-${index}`}>
                          <h3>{behavior.name_vi}</h3>
                          <p>{behavior.description}</p>
                          {behavior.evidence && <blockquote>“{behavior.evidence}”</blockquote>}
                          {behavior.explanation && <p>{behavior.explanation}</p>}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="report-muted">Chưa có dấu hiệu cụ thể được trích dẫn.</p>
                  )}
                </section>
                <section className="report-section">
                  <h2>Phân tích</h2>
                  <p>{result.summary}</p>
                </section>
                <section className="report-section">
                  <h2>Chưa xác minh</h2>
                  <ul>
                    {(result.unverified_information.length > 0
                      ? result.unverified_information
                      : ['Danh tính người gửi và thông tin bên ngoài chưa được xác minh.']
                    ).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
                  </ul>
                </section>
                <section className="report-section">
                  <h2>Giới hạn</h2>
                  <ul>
                    {(result.limitations.length > 0
                      ? result.limitations
                      : ['Kết quả chỉ mang tính tham khảo, không bảo đảm nội dung an toàn.']
                    ).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}
                  </ul>
                </section>
              </details>
            </div>
          </section>
        )}

        {screen === 'result' && (mode === 'image' || mode === 'audio') && (
          <section className="report-card" aria-labelledby="batch-report-title" aria-live="polite">
            <button type="button" className="back-button" onClick={() => setScreen('home')}>
              ← Quay lại tệp
            </button>
            <h2 className="report-section-heading">Mức độ an toàn</h2>
            {combinedPresentation ? (
              <div className={`report-status ${combinedPresentation.className}`}>
                <span className="risk-icon" aria-hidden="true">{combinedPresentation.icon}</span>
                <h1 id="batch-report-title">{combinedPresentation.label}</h1>
              </div>
            ) : (
              <div className="report-status risk-unknown">
                <span className="risk-icon" aria-hidden="true">!</span>
                <h1 id="batch-report-title">
                  {allMediaFailed
                    ? 'Dịch vụ phân tích chưa khả dụng'
                    : 'Chưa có kết quả phân tích'}
                </h1>
              </div>
            )}
            <p className="report-summary">{combinedSummary}</p>
            <div className="report-body">
              <section className="next-action">
                <h2>Bạn nên làm gì?</h2>
                <p>
                  {completedMedia.length === 0
                    ? 'Chưa có tệp nào được phân tích. Hãy xem lỗi của từng tệp hoặc thử lại; đây không phải kết luận an toàn.'
                    : safeCombinedRecommendation}
                </p>
              </section>
              <details className="report-details">
                <summary>Xem giải thích chi tiết</summary>
                <section className="report-section">
                  <h2>Trạng thái từng tệp</h2>
                  {mode === 'image' && currentBatch.length > 1 && (
                    <p>
                      Ảnh được kiểm tra theo thứ tự đã chọn. Nội dung giữa các ảnh chưa được ghép thành một cuộc hội thoại.
                    </p>
                  )}
                  <ul className="media-result-list">
                    {currentBatch.map((item) => (
                      <li className="media-result-item" key={item.id}>
                        <strong>{item.file.name}</strong>
                        <span>
                          {item.status === 'completed' && 'Đã phân tích'}
                          {item.status === 'processing' && 'Đang phân tích'}
                          {item.status === 'pending' && 'Chưa xử lý'}
                          {item.status === 'failed' && 'Phân tích thất bại'}
                          {item.status === 'invalid' && 'Không thể xử lý tệp'}
                        </span>
                        {item.error && <p>{item.error}</p>}
                        {item.status === 'failed' && (
                          <button
                            type="button"
                            className="retry-button"
                            onClick={() => void retryMediaFile(mode, item.id)}
                            disabled={loading}
                          >
                            Thử lại tệp này
                          </button>
                        )}
                        {item.diagnostics && (
                          <p className="diagnostic-note">
                            Mã hỗ trợ: {item.diagnostics.requestId ?? 'không có'}
                            {item.diagnostics.httpStatus !== undefined &&
                              ` · HTTP ${item.diagnostics.httpStatus}`}
                            {item.diagnostics.providerStatus !== undefined &&
                              ` · Nhà cung cấp ${item.diagnostics.providerStatus}`}
                            {item.diagnostics.stage && ` · Giai đoạn ${item.diagnostics.stage}`}
                            {item.diagnostics.errorCategory &&
                              ` · Loại lỗi ${item.diagnostics.errorCategory}`}
                            {item.diagnostics.durationMs !== undefined &&
                              ` · ${item.diagnostics.durationMs} ms`}
                            {item.diagnostics.retryCount !== undefined &&
                              ` · Đã thử lại ${item.diagnostics.retryCount} lần`}
                          </p>
                        )}
                        {item.result && (
                          <>
                            <h3>{riskPresentation[item.result.risk_level].label}</h3>
                            <p>{item.result.summary}</p>
                            {item.result.transcription_status && (
                              <p>
                                Bản ghi âm:{' '}
                                {item.result.transcription_status === 'COMPLETED' &&
                                  'đã nghe rõ lời nói chính.'}
                                {item.result.transcription_status === 'PARTIAL' &&
                                  'chỉ nghe rõ một phần.'}
                                {item.result.transcription_status === 'FAILED' &&
                                  'không nghe rõ lời nói.'}
                              </p>
                            )}
                            {item.result.detected_behaviors.map((behavior, index) => (
                              <div
                                className="evidence-item"
                                key={`${item.id}-${behavior.name_vi}-${index}`}
                              >
                                <h4>{behavior.name_vi}</h4>
                                <p>{behavior.description}</p>
                                {behavior.evidence && (
                                  <blockquote>“{behavior.evidence}”</blockquote>
                                )}
                                {behavior.explanation && <p>{behavior.explanation}</p>}
                              </div>
                            ))}
                            {item.result.unverified_information.length > 0 && (
                              <ul>
                                {item.result.unverified_information.map((detail, index) => (
                                  <li key={`${item.id}-unverified-${index}`}>{detail}</li>
                                ))}
                              </ul>
                            )}
                            {item.result.limitations.length > 0 && (
                              <ul>
                                {item.result.limitations.map((detail, index) => (
                                  <li key={`${item.id}-limitation-${index}`}>{detail}</li>
                                ))}
                              </ul>
                            )}
                          </>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              </details>
            </div>
          </section>
        )}

        {screen === 'menu' && (
          <section className="secondary-screen" aria-labelledby="menu-title">
            <h1 id="menu-title">Menu</h1>
            <nav className="secondary-menu" aria-label="Thông tin ứng dụng">
              <button type="button" onClick={() => openInformation('about')}>Giới thiệu</button>
              <button type="button" onClick={() => openInformation('instructions')}>Hướng dẫn</button>
              <button type="button" onClick={() => openInformation('privacy')}>Quyền riêng tư</button>
              <button type="button" onClick={() => openInformation('technical')}>Thông tin kỹ thuật</button>
              <button type="button" onClick={() => openInformation('settings')}>Cài đặt</button>
              {feedbackUrl ? (
                <a href={feedbackUrl} target="_blank" rel="noreferrer">Gửi góp ý ↗</a>
              ) : (
                <p>Chưa có biểu mẫu góp ý.</p>
              )}
            </nav>
          </section>
        )}

        {screen === 'information' && (
          <section className="secondary-screen" aria-labelledby="information-title">
            <button type="button" className="back-button" onClick={() => setScreen('menu')}>
              ← Quay lại menu
            </button>
            <h1 id="information-title">{informationContent[topic].title}</h1>
            {informationContent[topic].paragraphs.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </section>
        )}
      </main>
    </div>
  );
}
