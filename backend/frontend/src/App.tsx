import { useRef, useState } from 'react';

type InputMode = 'text' | 'image' | 'audio';
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
}

interface ScamAnalysisResponse extends AnalysisResult {}

interface URLCheckResponse {
  risk_level: string;
  message: string;
}

const riskPresentation: Record<
  RiskLevel,
  { icon: string; label: string; classes: string }
> = {
  HIGH_RISK: {
    icon: '⚠️',
    label: 'Nguy cơ cao',
    classes: 'border-red-300 bg-red-50 text-red-900',
  },
  SUSPICIOUS: {
    icon: '🔎',
    label: 'Có dấu hiệu đáng ngờ',
    classes: 'border-amber-300 bg-amber-50 text-amber-950',
  },
  LOW_RISK: {
    icon: '✓',
    label: 'Ít dấu hiệu đáng ngờ',
    classes: 'border-emerald-300 bg-emerald-50 text-emerald-950',
  },
  INSUFFICIENT_DATA: {
    icon: 'ℹ️',
    label: 'Chưa đủ thông tin',
    classes: 'border-blue-300 bg-blue-50 text-blue-950',
  },
};

const inputModes: { id: InputMode; icon: string; label: string }[] = [
  { id: 'text', icon: '✉️', label: 'Tin nhắn' },
  { id: 'image', icon: '🖼️', label: 'Hình ảnh' },
  { id: 'audio', icon: '🎙️', label: 'Âm thanh' },
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

function isStandaloneHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

export default function App() {
  const [mode, setMode] = useState<InputMode>('text');
  const [message, setMessage] = useState('');
  const [imageFile, setImageFile] = useState<File | null>(null);
  const [audioFile, setAudioFile] = useState<File | null>(null);
  const [context, setContext] = useState('');
  const [consent, setConsent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [showExplanation, setShowExplanation] = useState(false);
  const requestInFlight = useRef(false);
  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? '';

  function chooseMode(nextMode: InputMode) {
    setMode(nextMode);
    setError(null);
    setResult(null);
    setShowExplanation(false);
    setConsent(false);
  }

  function chooseImage(file: File | undefined) {
    setError(null);
    setResult(null);
    setShowExplanation(false);
    setConsent(false);
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
    setError(null);
    setResult(null);
    setShowExplanation(false);
    setConsent(false);
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

    const isImage = mode === 'image';
    const isAudio = mode === 'audio';
    const content = message.trim();
    const isUrl = mode === 'text' && isStandaloneHttpUrl(content);
    if (isImage && !imageFile) {
      setError('Vui lòng chọn ảnh JPG, PNG hoặc WEBP cần kiểm tra.');
      return;
    }
    if (isAudio && !audioFile) {
      setError('Vui lòng chọn tệp MP3, WAV hoặc M4A cần kiểm tra.');
      return;
    }
    if (mode === 'text' && !content) {
      setError('Vui lòng nhập tin nhắn hoặc đường dẫn cần kiểm tra.');
      return;
    }
    if ((isImage || isAudio) && !consent) {
      setError(
        isImage
          ? 'Vui lòng đồng ý trước khi gửi ảnh đến Google Gemini.'
          : 'Vui lòng đồng ý trước khi gửi âm thanh đến Google Gemini.',
      );
      return;
    }
    if (mode === 'text' && !isUrl && !consent) {
      setError(
        isImage
          ? 'Vui lòng đồng ý trước khi gửi ảnh đến Google Gemini.'
          : 'Vui lòng đồng ý trước khi gửi tin nhắn để phân tích.',
      );
      return;
    }

    requestInFlight.current = true;
    setLoading(true);
    setError(null);
    setResult(null);
    setShowExplanation(false);

    try {
      if (isAudio && audioFile) {
        const mimeType = getAudioMimeType(audioFile);
        if (!mimeType) throw new Error('Vui lòng chọn tệp MP3, WAV hoặc M4A.');
        const response = await fetch(
          `${apiBaseUrl}/api/v1/scam-analysis/audio?allow_external_processing=true`,
          {
            method: 'POST',
            headers: { 'Content-Type': mimeType },
            body: audioFile,
          },
        );
        if (!response.ok) {
          const errorBody: { detail?: unknown } = await response.json().catch(() => ({}));
          throw new Error(
            typeof errorBody.detail === 'string'
              ? errorBody.detail
              : `Không thể phân tích âm thanh (HTTP ${response.status}).`,
          );
        }
        const data: ScamAnalysisResponse = await response.json();
        setResult(data);
      } else if (isImage && imageFile) {
        const mimeType = getImageMimeType(imageFile);
        if (!mimeType) throw new Error('Vui lòng chọn ảnh JPG, PNG hoặc WEBP.');
        const response = await fetch(
          `${apiBaseUrl}/api/v1/scam-analysis/image?allow_external_processing=true`,
          {
            method: 'POST',
            headers: { 'Content-Type': mimeType },
            body: imageFile,
          },
        );
        if (!response.ok) {
          const errorBody: { detail?: unknown } = await response.json().catch(() => ({}));
          throw new Error(
            typeof errorBody.detail === 'string'
              ? errorBody.detail
              : `Không thể phân tích ảnh (HTTP ${response.status}).`,
          );
        }
        const data: ScamAnalysisResponse = await response.json();
        setResult(data);
      } else if (isUrl) {
        const response = await fetch(`${apiBaseUrl}/api/v1/check`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: content }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data: URLCheckResponse = await response.json();
        setResult({
          risk_level: data.risk_level === 'needs_review' ? 'SUSPICIOUS' : 'INSUFFICIENT_DATA',
          summary: data.message,
          detected_behaviors: [],
          recommendations: [
            data.risk_level === 'needs_review'
              ? 'Không mở liên kết hoặc nhập thông tin cá nhân.'
              : 'Tự xác minh đường dẫn qua kênh chính thức trước khi sử dụng.',
          ],
        });
      } else {
        const response = await fetch(`${apiBaseUrl}/api/v1/scam-analysis`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            content,
            context: context.trim() || null,
            allow_external_processing: true,
          }),
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data: ScamAnalysisResponse = await response.json();
        setResult(data);
      }
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? `Chưa thể phân tích${isAudio ? ' âm thanh' : ''}: ${requestError.message}`
          : 'Đã xảy ra lỗi không xác định. Vui lòng thử lại.',
      );
    } finally {
      requestInFlight.current = false;
      setLoading(false);
    }
  }

  const audioRiskLabels: Record<RiskLevel, string> = {
    LOW_RISK: 'Thấp',
    SUSPICIOUS: 'Trung bình',
    HIGH_RISK: 'Cao',
    INSUFFICIENT_DATA: 'Chưa xác định',
  };
  const presentation = result
    ? {
        ...riskPresentation[result.risk_level],
        label: mode === 'audio'
          ? audioRiskLabels[result.risk_level]
          : riskPresentation[result.risk_level].label,
      }
    : null;

  return (
    <div className="min-h-screen bg-sky-50 px-4 py-6 text-slate-950 sm:px-6 sm:py-10">
      <main className="mx-auto max-w-2xl">
        <header className="mb-8 flex items-center gap-3 sm:mb-10">
          <div
            aria-hidden="true"
            className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-blue-700 text-3xl text-white shadow-sm"
          >
            🛡️
          </div>
          <div>
            <p className="text-sm font-semibold text-blue-800">LÁ CHẮN NGƯỜI THÂN</p>
            <h1 className="text-xl font-bold tracking-tight sm:text-2xl">
              Cùng bạn kiểm tra điều đáng ngờ
            </h1>
          </div>
        </header>

        <section className="rounded-3xl border border-blue-100 bg-white p-5 shadow-sm sm:p-8">
          <h2 className="text-2xl font-bold sm:text-3xl">Bạn muốn kiểm tra điều gì?</h2>
          <p className="mt-3 text-lg leading-7 text-slate-700">
            Chọn loại nội dung, sau đó nhập tin nhắn hoặc tải ảnh, âm thanh lên để kiểm tra.
          </p>

          <div className="mt-6 grid grid-cols-3 gap-2 sm:gap-3" aria-label="Loại nội dung">
            {inputModes.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={mode === item.id}
                onClick={() => chooseMode(item.id)}
                className={`min-h-20 rounded-2xl border-2 px-2 py-3 text-center text-base font-bold transition focus-visible:outline focus-visible:outline-4 focus-visible:outline-blue-400 sm:min-h-24 sm:text-lg ${
                  mode === item.id
                    ? 'border-blue-700 bg-blue-50 text-blue-900'
                    : 'border-slate-200 bg-white text-slate-700 hover:border-blue-300'
                }`}
              >
                <span className="block text-2xl" aria-hidden="true">{item.icon}</span>
                <span>{item.label}</span>
              </button>
            ))}
          </div>

          {mode === 'text' ? (
            <div className="mt-6">
              <label htmlFor="message" className="block text-lg font-bold">
                Tin nhắn hoặc đường dẫn
              </label>
              <textarea
                id="message"
                value={message}
                onChange={(event) => setMessage(event.target.value)}
                maxLength={12000}
                rows={7}
                className="mt-2 w-full resize-y rounded-2xl border-2 border-slate-300 px-4 py-4 text-lg leading-7 text-slate-950 placeholder:text-slate-500 focus:border-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-100"
                placeholder="Dán tin nhắn hoặc đường dẫn bạn muốn kiểm tra"
              />
              <p className="mt-1 text-right text-sm text-slate-600">
                {message.length}/12000 ký tự
              </p>

              <details className="mt-3 rounded-xl border border-slate-200 bg-slate-50">
                <summary className="cursor-pointer px-4 py-3 text-base font-semibold text-blue-900">
                  Thêm bối cảnh (không bắt buộc)
                </summary>
                <div className="px-4 pb-4">
                  <label htmlFor="context" className="sr-only">Bối cảnh bổ sung</label>
                  <textarea
                    id="context"
                    value={context}
                    onChange={(event) => setContext(event.target.value)}
                    maxLength={4000}
                    rows={3}
                    className="w-full rounded-xl border-2 border-slate-300 px-4 py-3 text-base leading-6 focus:border-blue-700 focus:outline-none focus:ring-4 focus:ring-blue-100"
                    placeholder="Ví dụ: người gửi tự xưng là ai, họ yêu cầu bạn làm gì?"
                  />
                </div>
              </details>

              {!isStandaloneHttpUrl(message.trim()) && (
                <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-base leading-6">
                  <input
                    type="checkbox"
                    checked={consent}
                    onChange={(event) => setConsent(event.target.checked)}
                    className="mt-1 h-5 w-5 shrink-0 accent-blue-700"
                  />
                  <span>
                    Tôi đồng ý gửi tin nhắn đến dịch vụ AI để phân tích. Không nhập mật khẩu,
                    mã OTP hoặc thông tin tài chính.
                  </span>
                </label>
              )}

              <button
                type="button"
                onClick={() => void analyze()}
                disabled={loading || (!isStandaloneHttpUrl(message.trim()) && !consent)}
                className="mt-5 min-h-14 w-full rounded-2xl bg-blue-700 px-6 py-4 text-lg font-bold text-white shadow-sm transition hover:bg-blue-800 focus-visible:outline focus-visible:outline-4 focus-visible:outline-blue-300 disabled:cursor-not-allowed disabled:bg-slate-400 sm:w-auto sm:min-w-64"
              >
                {loading ? 'Đang kiểm tra...' : 'Kiểm tra ngay'}
              </button>
            </div>
          ) : mode === 'image' ? (
            <div className="mt-6">
              <label htmlFor="image-upload" className="block text-lg font-bold">
                Chọn ảnh cần kiểm tra
              </label>
              <p id="image-help" className="mt-1 text-base leading-6 text-slate-700">
                Hỗ trợ JPG, PNG, WEBP; dung lượng tối đa 10 MB.
              </p>
              <input
                id="image-upload"
                type="file"
                accept="image/jpeg,image/png,image/webp,.jpg,.jpeg,.png,.webp"
                aria-describedby="image-help"
                onChange={(event) => chooseImage(event.currentTarget.files?.[0])}
                className="mt-3 block w-full rounded-xl border-2 border-slate-300 bg-white px-3 py-3 text-base text-slate-800 file:mr-4 file:rounded-lg file:border-0 file:bg-blue-100 file:px-4 file:py-2 file:font-bold file:text-blue-900"
              />
              {imageFile && (
                <p className="mt-2 break-all text-base text-slate-700">
                  Đã chọn: <strong>{imageFile.name}</strong> (
                  {(imageFile.size / (1024 * 1024)).toFixed(1)} MB)
                </p>
              )}

              <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-base leading-6">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                  className="mt-1 h-5 w-5 shrink-0 accent-blue-700"
                />
                <span>
                  Tôi đồng ý gửi ảnh này đến Google Gemini để phân tích. Không tải ảnh chứa
                  thông tin cá nhân nhạy cảm nếu không cần thiết.
                </span>
              </label>

              <button
                type="button"
                onClick={() => void analyze()}
                disabled={loading || !imageFile || !consent}
                className="mt-5 min-h-14 w-full rounded-2xl bg-blue-700 px-6 py-4 text-lg font-bold text-white shadow-sm transition hover:bg-blue-800 focus-visible:outline focus-visible:outline-4 focus-visible:outline-blue-300 disabled:cursor-not-allowed disabled:bg-slate-400 sm:w-auto sm:min-w-64"
              >
                {loading ? 'Đang phân tích ảnh...' : 'Phân tích ảnh'}
              </button>
            </div>
          ) : (
            <div className="mt-6">
              <label htmlFor="audio-upload" className="block text-lg font-bold">
                Chọn bản ghi âm cần kiểm tra
              </label>
              <p id="audio-help" className="mt-1 text-base leading-6 text-slate-700">
                Hỗ trợ MP3, WAV, M4A; dung lượng tối đa 20 MB.
              </p>
              <input
                id="audio-upload"
                type="file"
                accept=".mp3,audio/mpeg,.wav,audio/wav,.m4a,audio/mp4"
                aria-describedby="audio-help"
                onChange={(event) => chooseAudio(event.currentTarget.files?.[0])}
                className="mt-3 block w-full rounded-xl border-2 border-slate-300 bg-white px-3 py-3 text-base text-slate-800 file:mr-4 file:rounded-lg file:border-0 file:bg-blue-100 file:px-4 file:py-2 file:font-bold file:text-blue-900"
              />
              {audioFile && (
                <p className="mt-2 break-all text-base text-slate-700">
                  Đã chọn: <strong>{audioFile.name}</strong> (
                  {(audioFile.size / (1024 * 1024)).toFixed(1)} MB)
                </p>
              )}

              <label className="mt-5 flex cursor-pointer items-start gap-3 rounded-2xl border border-blue-200 bg-blue-50 p-4 text-base leading-6">
                <input
                  type="checkbox"
                  checked={consent}
                  onChange={(event) => setConsent(event.target.checked)}
                  className="mt-1 h-5 w-5 shrink-0 accent-blue-700"
                />
                <span>
                  Tôi đồng ý gửi bản ghi âm đến Google Gemini để phiên âm và phân tích.
                  Máy chủ không lưu tệp âm thanh.
                </span>
              </label>

              <button
                type="button"
                onClick={() => void analyze()}
                disabled={loading || !audioFile || !consent}
                className="mt-5 min-h-14 w-full rounded-2xl bg-blue-700 px-6 py-4 text-lg font-bold text-white shadow-sm transition hover:bg-blue-800 focus-visible:outline focus-visible:outline-4 focus-visible:outline-blue-300 disabled:cursor-not-allowed disabled:bg-slate-400 sm:w-auto sm:min-w-64"
              >
                {loading ? 'Đang phân tích âm thanh...' : 'Phân tích âm thanh'}
              </button>
            </div>
          )}

          {error && (
            <p role="alert" className="mt-5 rounded-xl border border-red-300 bg-red-50 p-4 text-base font-semibold text-red-900">
              {error}
            </p>
          )}
        </section>

        {result && presentation && (
          <section aria-live="polite" className="mt-6 rounded-3xl border border-slate-200 bg-white p-5 shadow-sm sm:p-8">
            <div className={`flex items-center gap-4 rounded-2xl border-2 p-5 sm:p-6 ${presentation.classes}`}>
              <span className="text-4xl sm:text-5xl" aria-hidden="true">{presentation.icon}</span>
              <h2 className="text-2xl font-extrabold sm:text-3xl">{presentation.label}</h2>
            </div>

            {mode !== 'audio' && result.recommendations.length > 0 && (
              <ul
                aria-label="Lời khuyên"
                className="mt-3 space-y-1 text-sm leading-6 text-slate-700"
              >
                {result.recommendations.slice(0, 2).map((recommendation, index) => (
                  <li key={`${recommendation}-${index}`} className="flex gap-2">
                    <span aria-hidden="true">•</span>
                    <span>{recommendation}</span>
                  </li>
                ))}
              </ul>
            )}

            <button
              type="button"
              aria-expanded={showExplanation}
              aria-controls="analysis-explanation"
              onClick={() => setShowExplanation((visible) => !visible)}
              className="mt-5 min-h-12 rounded-xl border-2 border-blue-700 px-5 py-3 text-base font-bold text-blue-900 hover:bg-blue-50 focus-visible:outline focus-visible:outline-4 focus-visible:outline-blue-300"
            >
              {showExplanation ? 'Ẩn giải thích' : 'Xem giải thích'}
            </button>

            {showExplanation && (
              <div id="analysis-explanation" className="mt-5 space-y-5 border-t border-slate-200 pt-5">
                <div>
                  <h3 className="text-lg font-bold">Lý do</h3>
                  <p className="mt-2 text-base leading-7 text-slate-800">{result.summary}</p>
                </div>

                {result.detected_behaviors.length > 0 && (
                  <div>
                    <h3 className="text-lg font-bold">Dấu hiệu đáng chú ý</h3>
                    <ul className="mt-2 space-y-3">
                      {result.detected_behaviors.map((behavior, index) => (
                        <li key={`${behavior.name_vi}-${index}`} className="rounded-xl bg-slate-50 p-4">
                          <p className="font-bold">{behavior.name_vi}</p>
                          <p className="mt-1 text-base leading-6 text-slate-700">{behavior.explanation}</p>
                          <blockquote className="mt-2 border-l-4 border-blue-400 pl-3 text-base italic leading-6 text-slate-700">
                            “{behavior.evidence}”
                          </blockquote>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {(mode === 'audio'
                  ? result.recommendations.length > 0
                  : result.recommendations.length > 2) && (
                  <div>
                    <h3 className="text-lg font-bold">Bạn nên làm gì?</h3>
                    <ul className="mt-2 list-inside list-disc space-y-2 text-base leading-7 text-slate-800">
                      {(mode === 'audio'
                        ? result.recommendations
                        : result.recommendations.slice(2, 7)
                      ).map((recommendation, index) => (
                        <li key={`${recommendation}-${index}`}>{recommendation}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </section>
        )}

        <footer className="px-2 py-6 text-center text-sm leading-6 text-slate-600">
          Kết quả chỉ mang tính tham khảo. Nếu chưa chắc chắn, hãy hỏi người thân trước khi chuyển tiền hoặc chia sẻ thông tin.
        </footer>
      </main>
    </div>
  );
}
