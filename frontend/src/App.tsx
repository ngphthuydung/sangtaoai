
import { useEffect, useState } from 'react';

interface BackendHealth {
  status: string;
  service: string;
  version: string;
  environment: string;
  timestamp: string;
}
interface URLCheckResult {
  url: string;
  status: string;
  risk_level: string;
  message: string;
}

type Page = 'dashboard' | 'links' | 'messages' | 'history' | 'alerts' | 'settings';

const navigation: { id: Page; icon: string; label: string }[] = [
  { id: 'dashboard', icon: '▦', label: 'Tổng quan' },
  { id: 'links', icon: '🔗', label: 'Kiểm tra đường link' },
  { id: 'messages', icon: '💬', label: 'Phân tích tin nhắn' },
  { id: 'history', icon: '◷', label: 'Lịch sử kiểm tra' },
  { id: 'alerts', icon: '🔔', label: 'Trung tâm cảnh báo' },
  { id: 'settings', icon: '⚙️', label: 'Cài đặt' },
];

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [health, setHealth] = useState<BackendHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

const [urlInput, setUrlInput] = useState('');
const [urlResult, setUrlResult] = useState<URLCheckResult | null>(null);
const [urlLoading, setUrlLoading] = useState(false);
const [urlError, setUrlError] = useState<string | null>(null);

  const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

async function checkURL() {
  const url = urlInput.trim();

  if (!url) {
    setUrlError('Vui lòng nhập đường link cần kiểm tra.');
    return;
  }

  setUrlLoading(true);
  setUrlError(null);
  setUrlResult(null);

  try {
    const response = await fetch(`${apiBaseUrl}/api/v1/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data: URLCheckResult = await response.json();
    setUrlResult(data);
  } catch (err) {
    setUrlError(
      err instanceof Error
        ? `Không thể kiểm tra: ${err.message}`
        : 'Đã xảy ra lỗi không xác định.'
    );
  } finally {
    setUrlLoading(false);
  }
}

  async function checkHealth() {
    setLoading(true);
    setError(null);
    setHealth(null);

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/health`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data: BackendHealth = await response.json();
      setHealth(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Không thể kết nối máy chủ');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void checkHealth();
  }, []);

  const connected = !loading && !error && health?.status?.toLowerCase() === 'healthy';
  const pageTitle = navigation.find(item => item.id === page)?.label;

  function navigate(nextPage: Page) {
    setPage(nextPage);
    setSidebarOpen(false);
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 md:flex">
      {sidebarOpen && (
        <button
          className="fixed inset-0 z-20 bg-slate-950/50 md:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-label="Đóng menu"
        />
      )}

      <aside className={`${sidebarOpen ? 'translate-x-0' : '-translate-x-full'} fixed inset-y-0 left-0 z-30 flex w-72 flex-col bg-slate-950 text-white transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0`}>
        <div className="flex items-center gap-3 border-b border-white/10 px-6 py-7">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-sky-600 text-2xl">🛡️</div>
          <div>
            <h1 className="text-lg font-bold">Lá Chắn Người Thân</h1>
            <p className="text-xs text-slate-400">AI Security Platform</p>
          </div>
        </div>

        <nav className="flex-1 space-y-2 px-4 py-7" aria-label="Điều hướng chính">
          <p className="mb-4 px-3 text-xs font-bold uppercase tracking-widest text-slate-500">Workspace</p>
          {navigation.map(item => (
            <button
              key={item.id}
              onClick={() => navigate(item.id)}
              className={`flex w-full items-center gap-4 rounded-xl px-4 py-3 text-left text-sm font-medium transition ${
                page === item.id
                  ? 'bg-sky-600 text-white shadow-lg shadow-sky-900/30'
                  : 'text-slate-400 hover:bg-white/10 hover:text-white'
              }`}
            >
              <span className="w-6 text-center text-xl">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="border-t border-white/10 p-5">
          <div className="rounded-xl bg-white/5 p-4">
            <p className="text-xs text-slate-400">Trạng thái hệ thống</p>
            <p className="mt-2 flex items-center gap-2 text-sm font-semibold">
              <span className={`h-2.5 w-2.5 rounded-full ${connected ? 'bg-emerald-400' : loading ? 'bg-amber-400' : 'bg-rose-400'}`} />
              {loading ? 'Đang kết nối' : connected ? 'Đang hoạt động' : 'Cần kiểm tra'}
            </p>
          </div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-200 bg-white/95 px-5 py-4 backdrop-blur md:px-9">
          <div className="flex items-center gap-3">
            <button
              className="rounded-lg border border-slate-200 px-3 py-2 md:hidden"
              onClick={() => setSidebarOpen(true)}
              aria-label="Mở menu"
            >
              ☰
            </button>
            <div>
              <p className="text-xs text-slate-400">Lá Chắn Người Thân / Workspace</p>
              <h2 className="text-xl font-bold">{pageTitle}</h2>
            </div>
          </div>
          <div className="rounded-full bg-sky-50 px-4 py-2 text-xs font-bold text-sky-700">
            ✦ Modern AI
          </div>
        </header>

        <main className="mx-auto max-w-7xl space-y-7 p-5 md:p-9">
          {page === 'dashboard' ? (
            <>
              <section className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-slate-950 via-blue-950 to-sky-800 p-8 text-white shadow-xl md:p-11">
                <div className="relative z-10 max-w-2xl">
                  <p className="mb-4 text-sm font-semibold tracking-widest text-sky-300">AI-POWERED PROTECTION</p>
                  <h2 className="text-3xl font-bold leading-tight md:text-4xl">
                    An toàn trực tuyến, an tâm mỗi ngày.
                  </h2>
                  <p className="mt-4 text-slate-300">
                    Nền tảng hỗ trợ nhận diện dấu hiệu lừa đảo, bảo vệ bạn và những người thân yêu trong môi trường số.
                  </p>
                  <button
                    onClick={() => navigate('links')}
                    className="mt-7 rounded-xl bg-white px-6 py-3 font-bold text-slate-900 transition hover:bg-sky-100"
                  >
                    Bắt đầu kiểm tra →
                  </button>
                </div>
                <div className="pointer-events-none absolute -right-8 -top-12 text-[220px] opacity-10">🛡️</div>
              </section>

              <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                {[
                  { icon: '🛡️', label: 'Trạng thái bảo vệ', value: connected ? 'Sẵn sàng' : 'Chưa xác nhận', detail: 'Dựa trên kết nối Backend' },
                  { icon: '⚡', label: 'Phiên bản hệ thống', value: health?.version || '—', detail: 'Thông tin từ máy chủ' },
                  { icon: '🌐', label: 'Môi trường', value: health?.environment || '—', detail: 'Cấu hình hoạt động' },
                ].map(card => (
                  <div key={card.label} className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
                    <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-xl bg-sky-50 text-2xl">{card.icon}</div>
                    <p className="text-sm text-slate-500">{card.label}</p>
                    <h3 className="mt-2 text-2xl font-bold">{card.value}</h3>
                    <p className="mt-2 text-xs text-slate-400">{card.detail}</p>
                  </div>
                ))}
              </section>

              <section className="grid gap-5 lg:grid-cols-2">
                <div className="rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
                  <h3 className="text-lg font-bold">Công cụ bảo vệ</h3>
                  <p className="mt-1 text-sm text-slate-500">Các chức năng đang được phát triển.</p>
                  <div className="mt-6 space-y-3">
                    {[
                      { icon: '🔗', title: 'Kiểm tra đường link', page: 'links' as Page },
                      { icon: '💬', title: 'Phân tích tin nhắn', page: 'messages' as Page },
                      { icon: '🔔', title: 'Trung tâm cảnh báo', page: 'alerts' as Page },
                    ].map(tool => (
                      <button
                        key={tool.page}
                        onClick={() => navigate(tool.page)}
                        className="flex w-full items-center justify-between rounded-xl border border-slate-100 p-4 text-left transition hover:border-sky-200 hover:bg-sky-50"
                      >
                        <span className="flex items-center gap-3 font-medium">
                          <span className="text-xl">{tool.icon}</span>{tool.title}
                        </span>
                        <span className="text-slate-400">→</span>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <h3 className="text-lg font-bold">System Health</h3>
                    <button
                      onClick={() => void checkHealth()}
                      disabled={loading}
                      className="rounded-lg bg-sky-50 px-4 py-2 text-sm font-bold text-sky-700 hover:bg-sky-100 disabled:opacity-50"
                    >
                      {loading ? 'Đang kiểm tra...' : '↻ Kiểm tra lại'}
                    </button>
                  </div>

                  <div className={`mt-6 rounded-xl border p-5 ${connected ? 'border-emerald-200 bg-emerald-50' : 'border-amber-200 bg-amber-50'}`}>
                    <p className="font-bold">
                      {loading ? '⏳ Đang kết nối...' : connected ? '✅ Backend hoạt động bình thường' : '⚠️ Chưa xác nhận kết nối'}
                    </p>
                    {error && <p className="mt-2 break-words text-sm text-rose-700">{error}</p>}
                    <p className="mt-2 break-all text-xs text-slate-500">{apiBaseUrl}/api/v1/health</p>
                  </div>

                  <div className="mt-5 space-y-3 text-sm">
                    <div className="flex justify-between gap-3 border-b pb-3">
                      <span className="text-slate-500">Dịch vụ</span>
                      <span className="text-right font-medium">{health?.service || '—'}</span>
                    </div>
                    <div className="flex justify-between gap-3 border-b pb-3">
                      <span className="text-slate-500">Trạng thái</span>
                      <span className="font-semibold">{health?.status || '—'}</span>
                    </div>
                    <div className="flex justify-between gap-3">
                      <span className="text-slate-500">Thời gian phản hồi</span>
                      <span className="text-right text-xs">{health?.timestamp || '—'}</span>
                    </div>
                  </div>
                </div>
              </section>
            </>
                    ) : page === 'links' ? (
            <section className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm md:p-12">

            </section>
          ) : (
            <section className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm md:p-12"></section>
            <section className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm md:p-12">
              <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-2xl bg-sky-50 text-3xl">
                {navigation.find(item => item.id === page)?.icon}
              </div>
              <h2 className="text-2xl font-bold">{pageTitle}</h2>
              <p className="mt-3 max-w-xl leading-7 text-slate-500">
                Chức năng này đang được xây dựng trong các milestone tiếp theo.
                Hiện tại đây là giao diện điều hướng, chưa có khả năng phân tích hay phát hiện lừa đảo.
              </p>
              <button
                onClick={() => navigate('dashboard')}
                className="mt-7 rounded-xl bg-sky-600 px-5 py-3 font-semibold text-white hover:bg-sky-700"
              >
                ← Quay về tổng quan
              </button>
            </section>
          )}

          <footer className="pb-4 text-center text-xs text-slate-400">
            © 2026 Lá Chắn Người Thân · AI Security Platform · Development Preview
          </footer>
        </main>
      </div>
    </div>
  );
}
