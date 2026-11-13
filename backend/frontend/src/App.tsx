import { useRef, useState } from 'react';

type InputMode = 'text' | 'url' | 'image' | 'audio';
type RiskLevel = 'LOW_RISK' | 'SUSPICIOUS' | 'HIGH_RISK' | 'INSUFFICIENT_DATA';

interface DetectedBehavior {
  type?: string;
  name_vi: string;
  description: string;
  evidence: string;
  explanation: string;
  supported_by?: string[];
}

interface AnalysisResult {
  risk_level: RiskLevel;
  summary: string;
  detected_behaviors: DetectedBehavior[];
  recommendations: string[];
  unverified_information?: string[];
  limitations?: string[];
  analysis_method?: string;
  verification_status?: string;
  cross_check_status?: string;
  cross_check_summary?: string;
}

interface URLCheckResponse {
  url: string;
  status: string;
  risk_level: string;
  message: string;
}

const riskLevels = new Set<RiskLevel>([
  'LOW_RISK',
  'SUSPICIOUS',
  'HIGH_RISK',
  'INSUFFICIENT_DATA',
]);

const analysisMethodLabels: Record<string, string> = {
  GEMINI_CONTEXTUAL_ANALYSIS: 'Phân tích bằng Gemini',
  OPENAI_CONTEXTUAL_ANALYSIS: 'Phân tích bằng OpenAI',
  HYBRID_CONTEXTUAL_ANALYSIS: 'Phân tích kết hợp',
  LLM_NOT_CONFIGURED: 'Dịch vụ AI chưa được cấu hình',
  EXTERNAL_ANALYSIS_NOT_CONSENTED: 'Chưa đồng ý gửi nội dung tới dịch vụ AI',
  LLM_UNAVAILABLE: 'Dịch vụ AI hiện không khả dụng',
  INPUT_LIMIT_EXCEEDED: 'Nội dung vượt giới hạn xử lý',
};

const verificationLabels: Record<string, string> = {
  NOT_VERIFIED: 'Chưa xác minh độc lập',
};

const crossCheckLabels: Record<string, string> = {
  NOT_REQUESTED: 'Chưa thực hiện',
  CONFIRMED: 'Có kết quả xác nhận',
  DISAGREEMENT: 'Các kết quả chưa thống nhất',
  UNAVAILABLE: 'Không khả dụng',
  NOT_CONFIGURED: 'Chưa cấu hình',
};

interface InputModeOption {
  id: InputMode;
  icon: string;
  label: string;
  description: string;
}

const riskPresentation: Record<
  RiskLevel,
  { icon: string; label: string; classes: string }
> = {
  HIGH_RISK: {
    icon: '!',
    label: 'Nguy cơ cao',
    classes: 'risk-high',
  },
  SUSPICIOUS: {
    icon: '?',
    label: 'Có dấu hiệu đáng ngờ',
    classes: 'risk-suspicious',
  },
  LOW_RISK: {
    icon: '✓',
    label: 'Ít dấu hiệu được phát hiện',
    classes: 'risk-low',
  },
  INSUFFICIENT_DATA: {
    icon: 'i',
    label: 'Chưa đủ thông tin để kết luận',
    classes: 'risk-unknown',
  },
};

const inputModes: InputModeOption[] = [
  {
    id: 'text',
    icon: '✉',
    label: 'Tin nhắn',
    description: 'Dán SMS, email hoặc nội dung đáng ngờ',
  },
  {
    id: 'url',
    icon: '↗',
    label: 'Đường link',
    description: 'Kiểm tra một URL mà không mở trang đó',
  },
  {
    id: 'image',
    icon: '▧',
    label: 'Hình ảnh',
    description: 'Chọn ảnh chụp tin nhắn hoặc thông báo',
  },
  {
    id: 'audio',
    icon: '♫',
    label: 'Âm thanh',
    description: 'Chọn bản ghi âm cuộc gọi hoặc tin nhắn thoại',
  },
];

const maxImageSizeBytes = 10 * 1024 * 1024;
const maxAudioSizeBytes = 20 * 1024 * 1024;
const acceptedImageTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const audioMimeTypes: Record<string, string> = {
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  m4a: 'audio/mp4',
};

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
    return (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      Boolean(url.hostname)
    );
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

async function getApiError(response: Response, fallback: string): Promise<string> {
  try {
    const body: { detail?: unknown } = await response.json();
    if (typeof body.detail === 'string' && body.detail.trim()) return body.detail;
  } catch {
    // Use a concise fallback when the server does not return JSON.
  }
  return `${fallback} (HTTP ${response.status}).`;
}

async function requestApi(url: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 70_000);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      throw new Error('Phân tích mất quá nhiều thời gian. Vui lòng thử lại sau.');
    }
    if (error instanceof TypeError) {
      throw new Error('Không thể kết nối với máy chủ. Hãy kiểm tra mạng rồi thử lại.');
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function parseAnalysisResult(payload: unknown): AnalysisResult {
  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
  }
  const data = payload as Record<string, unknown>;
  if (
    typeof data.risk_level !== 'string' ||
    !riskLevels.has(data.risk_level as RiskLevel) ||
    typeof data.summary !== 'string' ||
    !Array.isArray(data.detected_behaviors) ||
    !Array.isArray(data.recommendations)
  ) {
    throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
  }

  const findings = data.detected_behaviors.map((item): DetectedBehavior => {
    if (typeof item !== 'object' || item === null) {
      throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
    }
    const finding = item as Record<string, unknown>;
    if (
      typeof finding.name_vi === 'string' &&
      typeof finding.description === 'string' &&
      typeof finding.evidence === 'string' &&
      typeof finding.explanation === 'string'
    ) {
      return {
        type: typeof finding.type === 'string' ? finding.type : undefined,
        name_vi: finding.name_vi,
        description: finding.description,
        evidence: finding.evidence,
        explanation: finding.explanation,
      };
    }
    throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
  });
  if (!data.recommendations.every((item) => typeof item === 'string')) {
    throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
  }
  const recommendations = data.recommendations as string[];
  const optionalStringList = (key: 'unverified_information' | 'limitations') => {
    if (!(key in data)) return [];
    if (
      !Array.isArray(data[key]) ||
      !data[key].every((item) => typeof item === 'string')
    ) {
      throw new Error('Máy chủ trả về kết quả không đúng định dạng. Vui lòng thử lại.');
    }
    return data[key] as string[];
  };
  const optionalString = (key: keyof AnalysisResult) =>
    typeof data[key] === 'string' ? data[key] as string : undefined;

  return {
    risk_level: data.risk_level as RiskLevel,
    summary: data.summary,
    detected_behaviors: findings,
    recommendations,
    unverified_information: optionalStringList('unverified_information'),
    limitations: optionalStringList('limitations'),
    analysis_method: optionalString('analysis_method'),
    verification_status: optionalString('verification_status'),
    cross_check_status: optionalString('cross_check_status'),
    cross_check_summary: optionalString('cross_check_summary'),
  };
}

async function readAnalysisResult(response: Response): Promise<AnalysisResult> {
  try {
    return parseAnalysisResult(await response.json());
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Máy chủ trả về')) throw error;
    throw new Error('Không đọc được kết quả từ máy chủ. Vui lòng thử lại.');
  }
}

export default function App() {
  const [mode, setMode] = useState<InputMode>('text');
  const [message, setMessage] = useState('');
  const [url, setUrl] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [context, setContext] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const requestInFlight = useRef(false);
  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? '';
  const feedbackUrl = getFeedbackUrl();

  function chooseMode(nextMode: InputMode) {
    if (loading) return;
    setMode(nextMode);
    setError(null);
    setResult(null);
    setConsent(false);
  }

  function resetResult() {
    setError(null);
    setResult(null);
    setConsent(false);
  }

  function chooseImage(file: File | undefined) {
    resetResult();
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
    resetResult();
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
      const target = mode === 'text' ? 'tin nhắn' : mode === 'image' ? 'ảnh' : 'âm thanh';
      setError(`Vui lòng đồng ý trước khi gửi ${target} đến dịch vụ AI.`);
      return;
    }

    requestInFlight.current = true;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let response: Response;
      if (mode === 'audio' && audioFile) {
        const mimeType = getAudioMimeType(audioFile);
        if (!mimeType) throw new Error('Vui lòng chọn tệp MP3, WAV hoặc M4A.');
        response = await requestApi(
          `${apiBaseUrl}/api/v1/scam-analysis/audio?allow_external_processing=true`,
          {
            method: 'POST',
            headers: { 'Content-Type': mimeType },
            body: audioFile,
          },
        );
        if (!response.ok) {
          throw new Error(await getApiError(response, 'Chưa thể phân tích âm thanh'));
        }
        setResult(await readAnalysisResult(response));
      } else if (mode === 'image' && imageFile) {
        const mimeType = getImageMimeType(imageFile);
        if (!mimeType) throw new Error('Vui lòng chọn ảnh JPG, PNG hoặc WEBP.');
        response = await requestApi(
          `${apiBaseUrl}/api/v1/scam-analysis/image?allow_external_processing=true`,
          {
            method: 'POST',
            headers: { 'Content-Type': mimeType },
            body: imageFile,
          },
        );
        if (!response.ok) {
          throw new Error(await getApiError(response, 'Chưa thể phân tích hình ảnh'));
        }
        setResult(await readAnalysisResult(response));
      } else if (mode === 'url') {
        response = await requestApi(`${apiBaseUrl}/api/v1/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: targetUrl }),
        });
        if (!response.ok) {
          throw new Error(await getApiError(response, 'Chưa thể kiểm tra đường link'));
        }
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
          throw new Error('Không đọc được kết quả kiểm tra đường link. Vui lòng thử lại.');
        }
        const needsReview = data.risk_level === 'needs_review';
        setResult({
          risk_level: needsReview ? 'SUSPICIOUS' : 'INSUFFICIENT_DATA',
          summary: data.message,
          detected_behaviors: needsReview
            ? [
                {
                  name_vi: 'Dấu hiệu cần kiểm tra',
                  description: 'Phân tích sơ bộ phát hiện tín hiệu trong địa chỉ URL.',
                  evidence: data.url,
                  explanation: data.message,
                },
              ]
            : [],
          recommendations: [
            needsReview
              ? 'Không mở liên kết hoặc nhập thông tin cá nhân, mật khẩu hay mã OTP.'
              : 'Chưa thể xác nhận đường link an toàn. Hãy tự xác minh qua kênh chính thức trước khi mở.',
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
        response = await requestApi(`${apiBaseUrl}/api/v1/scam-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content,
            context: context.trim() || null,
            allow_external_processing: true,
          }),
        });
        if (!response.ok) {
          throw new Error(await getApiError(response, 'Chưa thể phân tích tin nhắn'));
        }
        setResult(await readAnalysisResult(response));
      }
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Đã xảy ra lỗi không xác định. Vui lòng thử lại.',
      );
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  const presentation = result ? riskPresentation[result.risk_level] : null;
  const noFindings = result?.detected_behaviors.length === 0;
  const recommendations = result?.recommendations ?? [];
  const unverified = result?.unverified_information ?? [];
  const limitations = result?.limitations ?? [];

  return (
    <div className="app-shell">
      <header className="site-header">
        <a className="brand" href="#main" aria-label="Lá Chắn Người Thân - về nội dung chính">
          <span className="brand-mark" aria-hidden="true">✓</span>
          <span>
            <span className="brand-name">Lá Chắn Người Thân</span>
            <span className="brand-caption">Cùng gia đình nhận diện điều đáng ngờ</span>
          </span>
        </a>
        <div className="header-actions">
          <span className="preview-badge">BẢN XEM TRƯỚC</span>
          {feedbackUrl ? (
            <a className="feedback-link" href={feedbackUrl} target="_blank" rel="noreferrer">
              Gửi góp ý <span aria-hidden="true">↗</span>
            </a>
          ) : (
            <button
              className="feedback-link feedback-disabled"
              type="button"
              disabled
              title="Chưa cấu hình biểu mẫu góp ý"
            >
              Gửi góp ý
            </button>
          )}
        </div>
      </header>

      <main id="main" className="main-content">
        <section className="welcome-panel" aria-labelledby="page-title">
          <div className="welcome-copy">
            <p className="eyebrow">BÌNH TĨNH KIỂM TRA TRƯỚC KHI HÀNH ĐỘNG</p>
            <h1 id="page-title">Có điều gì khiến bạn băn khoăn?</h1>
            <p>
              Chọn nội dung bạn muốn kiểm tra. Chúng tôi sẽ giúp chỉ ra dấu hiệu đáng chú ý
              và việc bạn có thể làm tiếp theo.
            </p>
          </div>
          <div className="welcome-shield" aria-hidden="true">✓</div>
          <div className="safety-note">
            <span className="safety-icon" aria-hidden="true">i</span>
            <p>
              Đừng vội chuyển tiền hoặc chia sẻ mật khẩu, mã OTP. Khi chưa chắc chắn,
              hãy hỏi người thân và xác minh qua số điện thoại chính thức.
            </p>
          </div>
        </section>

        <section className="workspace-card" aria-labelledby="choose-title">
          <div className="section-heading">
            <span className="step-number" aria-hidden="true">1</span>
            <div>
              <h2 id="choose-title">Bạn muốn kiểm tra loại nào?</h2>
              <p>Chọn một mục bên dưới để bắt đầu.</p>
            </div>
          </div>

          <div className="mode-grid" role="group" aria-label="Chọn loại nội dung cần kiểm tra">
            {inputModes.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={mode === item.id}
                onClick={() => chooseMode(item.id)}
                disabled={loading}
                className={`mode-card ${mode === item.id ? 'mode-card-active' : ''}`}
              >
                <span className="mode-icon" aria-hidden="true">{item.icon}</span>
                <span className="mode-copy">
                  <span className="mode-label">{item.label}</span>
                  <span className="mode-description">{item.description}</span>
                </span>
                <span className="mode-check" aria-hidden="true">{mode === item.id ? '✓' : ''}</span>
              </button>
            ))}
          </div>

          <div className="form-divider" />
          <div className="section-heading form-heading">
            <span className="step-number" aria-hidden="true">2</span>
            <div>
              <h2>
                {mode === 'text' && 'Dán nội dung tin nhắn'}
                {mode === 'url' && 'Dán đường link cần kiểm tra'}
                {mode === 'image' && 'Chọn hình ảnh cần kiểm tra'}
                {mode === 'audio' && 'Chọn bản ghi âm cần kiểm tra'}
              </h2>
              <p>
                {mode === 'url'
                  ? 'Chúng tôi chỉ kiểm tra địa chỉ; trang web sẽ không được mở.'
                  : 'Không nhập hoặc tải lên thông tin nhạy cảm nếu không cần thiết.'}
              </p>
            </div>
          </div>

          {mode === 'text' && (
            <div className="input-panel">
              <label htmlFor="message" className="field-label">Nội dung tin nhắn, email hoặc lời nhắn</label>
              <textarea
                id="message"
                value={message}
                onChange={(event) => {
                  setMessage(event.target.value);
                  setError(null);
                  setResult(null);
                }}
                maxLength={12000}
                rows={6}
                className="text-input"
                placeholder="Dán nội dung bạn nhận được vào đây..."
                aria-describedby="message-count"
              />
              <div id="message-count" className="field-meta">
                <span>Tối đa 12.000 ký tự</span>
                <span>{message.length.toLocaleString('vi-VN')}/12.000</span>
              </div>

              <details className="context-details">
                <summary>Thêm bối cảnh (không bắt buộc)</summary>
                <div className="context-content">
                  <label htmlFor="context" className="field-label">Bạn biết gì về người gửi hoặc tình huống?</label>
                  <textarea
                    id="context"
                    value={context}
                    onChange={(event) => {
                      setContext(event.target.value);
                      setResult(null);
                    }}
                    maxLength={4000}
                    rows={3}
                    className="text-input context-input"
                    placeholder="Ví dụ: người gửi tự xưng là ai, họ yêu cầu bạn làm gì?"
                  />
                </div>
              </details>
            </div>
          )}

          {mode === 'url' && (
            <div className="input-panel">
              <label htmlFor="url" className="field-label">Địa chỉ đường link (URL)</label>
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
                  setError(null);
                  setResult(null);
                }}
                className="text-input single-line-input"
                placeholder="Ví dụ: https://example.com"
              />
              <p className="field-help">
                Chỉ gửi địa chỉ URL tới máy chủ của ứng dụng để kiểm tra cơ bản.
                Không mở trang web, không xác minh được chủ sở hữu tên miền.
              </p>
            </div>
          )}

          {mode === 'image' && (
            <div className="input-panel">
              <label htmlFor="image-upload" className="field-label">Tệp hình ảnh</label>
              <p id="image-help" className="field-help">JPG, PNG hoặc WEBP · tối đa 10 MB</p>
              <input
                id="image-upload"
                type="file"
                accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp"
                aria-describedby="image-help"
                onChange={(event) => chooseImage(event.currentTarget.files?.[0])}
                className="file-input"
              />
              {imageFile && (
                <p className="selected-file">
                  <span aria-hidden="true">▧</span>
                  <span><strong>{imageFile.name}</strong> · {(imageFile.size / (1024 * 1024)).toFixed(1)} MB</span>
                </p>
              )}
            </div>
          )}

          {mode === 'audio' && (
            <div className="input-panel">
              <label htmlFor="audio-upload" className="field-label">Tệp âm thanh</label>
              <p id="audio-help" className="field-help">MP3, WAV hoặc M4A · tối đa 20 MB</p>
              <input
                id="audio-upload"
                type="file"
                accept=".mp3,audio/mpeg,.wav,audio/wav,.m4a,audio/mp4"
                aria-describedby="audio-help"
                onChange={(event) => chooseAudio(event.currentTarget.files?.[0])}
                className="file-input"
              />
              {audioFile && (
                <p className="selected-file">
                  <span aria-hidden="true">♫</span>
                  <span><strong>{audioFile.name}</strong> · {(audioFile.size / (1024 * 1024)).toFixed(1)} MB</span>
                </p>
              )}
            </div>
          )}

          {mode !== 'url' && (
            <label className="consent-box">
              <input
                type="checkbox"
                checked={consent}
                onChange={(event) => setConsent(event.target.checked)}
              />
              <span>
                {mode === 'text' && 'Tôi đồng ý gửi nội dung tin nhắn đến dịch vụ AI để phân tích.'}
                {mode === 'image' && 'Tôi đồng ý gửi hình ảnh này đến Google Gemini để phân tích.'}
                {mode === 'audio' && 'Tôi đồng ý gửi bản ghi âm này đến Google Gemini để phiên âm và phân tích.'}
                <span className="consent-note"> Không gửi mật khẩu, mã OTP hoặc thông tin tài chính nếu không cần thiết.</span>
              </span>
            </label>
          )}

          {error && (
            <div className="error-message" role="alert">
              <span aria-hidden="true">!</span>
              <p>{error}</p>
            </div>
          )}

          {loading && (
            <div className="loading-message" role="status" aria-live="polite">
              <span className="loading-spinner" aria-hidden="true" />
              <span>
                {mode === 'text' && 'Đang đọc nội dung và tìm dấu hiệu đáng chú ý…'}
                {mode === 'url' && 'Đang kiểm tra các tín hiệu cơ bản của đường link…'}
                {mode === 'image' && 'Đang gửi ảnh và phân tích chữ hiển thị…'}
                {mode === 'audio' && 'Đang gửi bản ghi âm để phiên âm và phân tích…'}
                <small>Quá trình có thể mất một chút thời gian. Vui lòng chờ.</small>
              </span>
            </div>
          )}

          <div className="submit-row">
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
              {loading ? 'Đang kiểm tra…' : 'Kiểm tra ngay'}
              {!loading && <span aria-hidden="true">→</span>}
            </button>
            <p className="submit-note">Kết quả là thông tin tham khảo, không thay thế việc xác minh.</p>
          </div>
        </section>

        {result && presentation && (
          <section className="report-card" aria-labelledby="report-title" aria-live="polite">
            <div className={`report-status ${presentation.classes}`}>
              <span className="risk-icon" aria-hidden="true">{presentation.icon}</span>
              <div>
                <p className="eyebrow">KẾT QUẢ KIỂM TRA</p>
                <h2 id="report-title">{presentation.label}</h2>
              </div>
            </div>

            <div className="report-body">
              <section className="report-section">
                <h3>Tóm tắt</h3>
                <p>{result.summary}</p>
              </section>

              <section className="report-section">
                <h3>Dấu hiệu đáng chú ý</h3>
                {result.detected_behaviors.length > 0 ? (
                  <ul className="finding-list">
                    {result.detected_behaviors.map((behavior, index) => (
                      <li className="finding-card" key={`${behavior.name_vi}-${index}`}>
                        <div className="finding-title-row">
                          <span className="finding-dot" aria-hidden="true">!</span>
                          <h4>{behavior.name_vi}</h4>
                        </div>
                        <p>{behavior.description}</p>
                        {behavior.evidence && (
                          <blockquote>
                            <span className="evidence-label">Bằng chứng trong nội dung</span>
                            <span>“{behavior.evidence}”</span>
                          </blockquote>
                        )}
                        {behavior.explanation && <p className="finding-explanation">{behavior.explanation}</p>}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="report-muted">
                    Chưa có dấu hiệu cụ thể được trích dẫn. Điều này không chứng minh nội dung an toàn.
                  </p>
                )}
              </section>

              <section className="report-section">
                <h3>Bạn nên làm gì?</h3>
                {recommendations.length > 0 ? (
                  <ul className="recommendation-list">
                    {recommendations.map((recommendation, index) => (
                      <li key={`${recommendation}-${index}`}>
                        <span aria-hidden="true">✓</span>{recommendation}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="report-muted">Chưa có khuyến nghị cụ thể. Hãy xác minh qua kênh chính thức.</p>
                )}
              </section>

              <div className="report-details-grid">
                <section className="report-section detail-panel">
                  <h3>Thông tin chưa xác minh</h3>
                  {unverified.length > 0 ? (
                    <ul>{unverified.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                  ) : (
                    <p className="report-muted">Danh tính, tổ chức, website và thông tin bên ngoài chưa được xác minh.</p>
                  )}
                  {result.verification_status && (
                        <p className="verification-note">
                          Trạng thái: {verificationLabels[result.verification_status] ?? result.verification_status}
                        </p>
                  )}
                </section>
                <section className="report-section detail-panel">
                  <h3>Giới hạn</h3>
                  {limitations.length > 0 ? (
                    <ul>{limitations.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                  ) : (
                    <p className="report-muted">AI có thể bỏ sót hoặc diễn giải sai. Hãy xác minh độc lập.</p>
                  )}
                </section>
              </div>

              {result.cross_check_summary && (
                <p className="cross-check-note">
                  Kiểm tra chéo: {result.cross_check_summary}
                    {result.cross_check_status
                      ? ` (${crossCheckLabels[result.cross_check_status] ?? result.cross_check_status})`
                      : ''}
                </p>
              )}
              {result.analysis_method && (
                  <p className="method-note">
                    Phương thức phân tích: {analysisMethodLabels[result.analysis_method] ?? result.analysis_method}
                  </p>
              )}
              {noFindings && result.risk_level !== 'INSUFFICIENT_DATA' && (
                <p className="caution-note">
                  Không có bằng chứng cụ thể được xác nhận trong nội dung. Đừng xem kết quả này là bảo đảm an toàn.
                </p>
              )}
            </div>
          </section>
        )}

        <footer className="site-footer">
          <p>
            Lá Chắn Người Thân chỉ hỗ trợ nhận diện dấu hiệu. Không công cụ nào có thể xác minh
            chắc chắn người gửi hoặc bảo đảm nội dung an toàn.
          </p>
          {feedbackUrl ? (
            <a href={feedbackUrl} target="_blank" rel="noreferrer">Gửi góp ý cho nhóm <span aria-hidden="true">↗</span></a>
          ) : (
            <span className="footer-feedback">Góp ý chưa khả dụng — nhóm chưa cấu hình biểu mẫu.</span>
          )}
        </footer>
      </main>
    </div>
  );
}
