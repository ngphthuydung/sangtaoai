import { useRef, useState } from 'react';
import {
  isTransientGatewayResponse,
  retryTransientGatewayRequest,
} from './requestRetry';

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
    label: 'Ít dấu hiệu được phát hiện',
    className: 'risk-low',
  },
  INSUFFICIENT_DATA: {
    icon: 'i',
    label: 'Chưa đủ thông tin',
    className: 'risk-unknown',
  },
};

const inputOptions: { id: InputMode; icon: string; label: string }[] = [
  { id: 'text', icon: '✉', label: 'Tin nhắn' },
  { id: 'url', icon: '↗', label: 'Đường link' },
  { id: 'image', icon: '▧', label: 'Hình ảnh' },
  { id: 'audio', icon: '♫', label: 'Âm thanh' },
];

const maxImageSizeBytes = 10 * 1024 * 1024;
const maxAudioSizeBytes = 20 * 1024 * 1024;
const acceptedImageTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const audioMimeTypes: Record<string, string> = {
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  m4a: 'audio/mp4',
};

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
      'Ứng dụng không lưu nội dung bạn nhập vào phần cài đặt. Bạn cần đồng ý mỗi lần gửi tin nhắn, hình ảnh hoặc âm thanh để phân tích.',
      'Không có tùy chọn nào thay đổi việc xử lý dữ liệu ở màn hình này.',
    ],
  },
};

const feedbackUrl = getFeedbackUrl();

function getImageMimeType(file: File): string | null {
  if (acceptedImageTypes.has(file.type)) return file.type;
  const extension = file.name.toLowerCase().split('.').pop();
  if (extension === 'jpg' || extension === 'jpeg') return 'image/jpeg';
  if (extension === 'png') return 'image/png';
  if (extension === 'webp') return 'image/webp';
  return null;
}

function getAudioMimeType(file: File): string | null {
  const extension = file.name.toLowerCase().split('.').pop();
  return extension ? audioMimeTypes[extension] ?? null : null;
}

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

  constructor(
    message: string,
    canRetry: boolean,
  ) {
    super(message);
    this.name = 'RequestFailure';
    this.canRetry = canRetry;
  }
}

async function getApiError(response: Response, fallback: string): Promise<string> {
  try {
    const body: { detail?: unknown } = await response.json();
    if (typeof body.detail === 'string' && body.detail.trim()) return body.detail;
  } catch {
    // Gateway errors are handled separately; other responses use a safe fallback.
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

  return retryTransientGatewayRequest(
    request,
    isTransientGatewayResponse,
    (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds)),
  );
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
      !['COMPLETED', 'NOT_ANALYZED', 'FAILED'].includes(String(data.analysis_status)))
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
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [context, setContext] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [canRetry, setCanRetry] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const requestInFlight = useRef(false);
  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? '';

  function clearRequestMessage() {
    setError(null);
    setCanRetry(false);
    setResult(null);
  }

  function chooseMode(nextMode: InputMode) {
    if (loading) return;
    setMode(nextMode);
    clearRequestMessage();
    setConsent(false);
  }

  function chooseImage(file: File | undefined) {
    clearRequestMessage();
    if (!file) {
      setImageFile(null);
      return;
    }
    if (!getImageMimeType(file)) {
      setImageFile(null);
      setError('Vui lòng chọn ảnh JPG, PNG hoặc WEBP.');
      return;
    }
    if (file.size > maxImageSizeBytes) {
      setImageFile(null);
      setError('Ảnh vượt quá giới hạn 10 MB. Vui lòng chọn ảnh nhỏ hơn.');
      return;
    }
    setImageFile(file);
  }

  function chooseAudio(file: File | undefined) {
    clearRequestMessage();
    if (!file) {
      setAudioFile(null);
      return;
    }
    if (!getAudioMimeType(file)) {
      setAudioFile(null);
      setError('Vui lòng chọn tệp MP3, WAV hoặc M4A.');
      return;
    }
    if (file.size > maxAudioSizeBytes) {
      setAudioFile(null);
      setError('Âm thanh vượt quá giới hạn 20 MB. Vui lòng chọn tệp nhỏ hơn.');
      return;
    }
    setAudioFile(file);
  }

  async function analyze() {
    if (requestInFlight.current) return;

    const content = message.trim();
    const targetUrl = url.trim();
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
    if (mode === 'image' && !imageFile) {
      setError('Vui lòng chọn ảnh JPG, PNG hoặc WEBP cần kiểm tra.');
      return;
    }
    if (mode === 'audio' && !audioFile) {
      setError('Vui lòng chọn tệp MP3, WAV hoặc M4A cần kiểm tra.');
      return;
    }
    if (mode !== 'url' && !consent) {
      setError(`Vui lòng đồng ý trước khi gửi ${getInputLabel(mode).toLowerCase()} đến dịch vụ AI.`);
      return;
    }

    requestInFlight.current = true;
    setLoading(true);
    setError(null);
    setCanRetry(false);
    setResult(null);

    try {
      let response: Response;
      if (mode === 'audio' && audioFile) {
        const mimeType = getAudioMimeType(audioFile);
        if (!mimeType) throw new RequestFailure('Vui lòng chọn tệp MP3, WAV hoặc M4A.', false);
        response = await requestApi(
          `${apiBaseUrl}/api/v1/scam-analysis/audio?allow_external_processing=true`,
          { method: 'POST', headers: { 'Content-Type': mimeType }, body: audioFile },
        );
      } else if (mode === 'image' && imageFile) {
        const mimeType = getImageMimeType(imageFile);
        if (!mimeType) throw new RequestFailure('Vui lòng chọn ảnh JPG, PNG hoặc WEBP.', false);
        response = await requestApi(
          `${apiBaseUrl}/api/v1/scam-analysis/image?allow_external_processing=true`,
          { method: 'POST', headers: { 'Content-Type': mimeType }, body: imageFile },
        );
      } else if (mode === 'url') {
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

      if (!response.ok) {
        const responseMessage =
          response.status >= 500
            ? 'Dịch vụ chưa thể xử lý yêu cầu. Đây không phải kết luận an toàn.'
            : await getApiError(response, 'Chưa thể kiểm tra nội dung');
        throw new RequestFailure(responseMessage, response.status >= 500);
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
                  <p id="image-help" className="field-help">JPG, PNG hoặc WEBP · tối đa 10 MB</p>
                  <input
                    id="image-upload"
                    type="file"
                    accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp"
                    aria-describedby="image-help"
                    onChange={(event) => chooseImage(event.currentTarget.files?.[0])}
                    className="file-input"
                  />
                  {imageFile && <p className="selected-file">{imageFile.name}</p>}
                </>
              )}
              {mode === 'audio' && (
                <>
                  <label htmlFor="audio-upload" className="field-label">Chọn tệp âm thanh</label>
                  <p id="audio-help" className="field-help">MP3, WAV hoặc M4A · tối đa 20 MB</p>
                  <input
                    id="audio-upload"
                    type="file"
                    accept=".mp3,audio/mpeg,.wav,audio/wav,.m4a,audio/mp4"
                    aria-describedby="audio-help"
                    onChange={(event) => chooseAudio(event.currentTarget.files?.[0])}
                    className="file-input"
                  />
                  {audioFile && <p className="selected-file">{audioFile.name}</p>}
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
                (mode === 'image' && (!imageFile || !consent)) ||
                (mode === 'audio' && (!audioFile || !consent))
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
            <div className={`report-status ${presentation.className}`}>
              <span className="risk-icon" aria-hidden="true">{presentation.icon}</span>
              <h1 id="report-title">{presentation.label}</h1>
            </div>
            <div className="report-body">
              <p className="report-summary">{result.summary}</p>
              {result.detected_behaviors.length > 0 && (
                <section className="report-section">
                  <h2>Dấu hiệu cần chú ý</h2>
                  <ul className="finding-list">
                    {result.detected_behaviors.slice(0, 3).map((behavior, index) => (
                      <li className="finding-card" key={`${behavior.name_vi}-${index}`}>
                        <h3>{behavior.name_vi}</h3>
                        <p>{behavior.description}</p>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              <section className="next-action">
                <h2>Bạn nên làm gì?</h2>
                <p>
                  {result.recommendations[0] ??
                    'Hãy xác minh qua kênh chính thức trước khi hành động.'}
                </p>
              </section>
              <details className="report-details">
                <summary>Xem chi tiết</summary>
                {result.detected_behaviors.some((behavior) => behavior.evidence) && (
                  <section className="report-section">
                    <h2>Bằng chứng</h2>
                    {result.detected_behaviors.map((behavior, index) => (
                      <div className="evidence-item" key={`${behavior.name_vi}-evidence-${index}`}>
                        <h3>{behavior.name_vi}</h3>
                        {behavior.evidence && <blockquote>“{behavior.evidence}”</blockquote>}
                        {behavior.explanation && <p>{behavior.explanation}</p>}
                      </div>
                    ))}
                  </section>
                )}
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
