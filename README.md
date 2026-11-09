# Lá Chắn Người Thân (Vietnamese Anti-Scam AI Platform)

> **Dự án Trí tuệ Nhân tạo Đa tầng Bảo vệ Người dùng (đặc biệt là Người cao tuổi và Gia đình) trước các Thủ đoạn Lừa đảo Trực tuyến tại Việt Nam.**

---

## 📌 Tổng Quan Cấu Trúc Dự Án (Monorepo Độc Lập)

Dự án được phân chia độc lập hoàn toàn giữa Backend và Frontend:

```text
la-chan-nguoi-than/
├── backend/                       # Máy chủ & Trí tuệ Nhân tạo (Python FastAPI)
│   ├── app/
│   │   ├── api/v1/health.py       # API kiểm tra hệ thống: GET /api/v1/health
│   │   ├── core/config.py         # Quản lý cấu hình biến môi trường an toàn (Pydantic Settings)
│   │   └── main.py                # Điểm khởi chạy của Backend FastAPI & CORS
│   ├── tests/test_health.py       # Bộ kiểm thử tự động với Pytest
│   ├── requirements.txt           # Danh mục thư viện Python
│   ├── .env.example               # Mẫu biến môi trường an toàn
│   └── .env                       # Biến môi trường cục bộ (không commit Git)
│
├── frontend/                      # Giao diện Web Responsive (React + TypeScript + Tailwind CSS)
│   ├── src/
│   │   ├── App.tsx                # Giao diện kiểm tra kết nối hệ thống
│   │   ├── main.tsx               # Điểm khởi chạy của React
│   │   └── index.css              # Cấu hình Tailwind CSS
│   ├── package.json               # Danh mục thư viện Frontend
│   ├── tailwind.config.js         # Cấu hình giao diện & bảng màu
│   ├── .env.example               # Mẫu cấu hình URL Backend cho Frontend
│   └── .env                       # Cấu hình cục bộ (không commit Git)
│
├── .gitignore                     # Bảo vệ thông tin bí mật, loại bỏ .env và node_modules
└── README.md                      # Tài liệu hướng dẫn này
```

---

## 🚀 Hướng Dẫn Khởi Chạy Dành Cho Người Mới Bắt Đầu

### 1. Chuẩn bị Môi Trường
* Đã cài đặt **Python 3.10+** (đã kiểm thử tương thích tốt với Python 3.15).
* Đã cài đặt **Node.js 18+** và **npm**.

---

### 2. Khởi Chạy Backend (FastAPI)

Mở một cửa sổ dòng lệnh (Terminal / PowerShell) tại thư mục gốc của dự án:

```powershell
# Bước 1: Di chuyển vào thư mục backend
cd backend

# Bước 2: Kích hoạt môi trường ảo Python đã tạo
# Trên Windows (PowerShell):
.venv\Scripts\Activate.ps1
# (Hoặc trên Command Prompt cmd):
# .venv\Scripts\activate.bat

# Bước 3: Khởi chạy máy chủ FastAPI
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

* **Trang tài liệu API tự động (Swagger UI):** Mở trình duyệt truy cập `http://127.0.0.1:8000/docs`
* **Kiểm tra trạng thái Backend:** Truy cập `http://127.0.0.1:8000/api/v1/health` hoặc qua frontend tại `http://localhost:5173/api/v1/health`

#### Chạy kiểm thử tự động Backend (Pytest):
```powershell
cd backend
.venv\Scripts\pytest tests -v
```

---

### 3. Khởi Chạy Frontend (React + Vite + TypeScript)

Mở một cửa sổ dòng lệnh (Terminal / PowerShell) **thứ hai**:

```powershell
# Bước 1: Di chuyển vào thư mục frontend
cd frontend

# Bước 2: Khởi chạy máy chủ phát triển Vite
npm run dev -- --host 0.0.0.0
```

* Truy cập giao diện trên trình duyệt tại địa chỉ: `http://localhost:5173`
* Trong môi trường phát triển, Vite chuyển tiếp `/api` tới backend trên cổng 8000; trình duyệt gọi API cùng origin để tránh vấn đề CORS và xác thực forwarded port. Có thể đặt `VITE_API_BASE_URL` nếu cần gọi API trực tiếp.

---

## 🔒 Quy Tắc Bảo Mật Đã Thiết Lập
1. **Tuyệt đối không lưu API Key bí mật ở Frontend:** Mọi thao tác AI (OpenAI/Gemini) và Cơ sở dữ liệu bắt buộc xử lý tại Backend.
2. **Quản lý biến môi trường an toàn:** File `.env` chứa mật khẩu đã được tự động thêm vào `.gitignore` để tránh bị đẩy lên kho mã nguồn công khai.
3. **CORS:** Các request từ frontend phát triển đi qua Vite proxy cùng origin; nếu cấu hình gọi API trực tiếp, hãy chỉ cho phép các origin frontend cần thiết.

---

## 📋 Trạng Thái Tiến Độ
* [x] **Milestone 1:** Khởi tạo khung dự án độc lập, cấu hình an toàn & API Health Check (Hoàn thành).
* [ ] **Milestone 2:** Thiết lập Cơ sở dữ liệu PostgreSQL + pgvector & Models tri thức lừa đảo.
* [ ] **Milestone 3:** Xây dựng Động cơ Phân tích AI Đa tầng (Modular Hybrid AI Engine).
* [ ] **Milestone 4:** Bộ Kiểm thử Độc lập (Evaluation Suite) với 300 - 500 mẫu tiếng Việt.
* [ ] **Milestone 5:** Giao diện Web thân thiện Người cao tuổi (Senior-Friendly UI).
* [ ] **Milestone 6:** Bộ Thu thập & Cổng Kiểm duyệt Tin tức (Collector & Moderation).
* [ ] **Milestone 7:** Cấu hình Capacitor & Đóng gói Ứng dụng Android APK.

---

## Nền tảng Hybrid AI (Backend)

Backend có các adapter OpenAI và Gemini cùng endpoint `POST /api/v1/scam-analysis`. Mỗi yêu cầu sử dụng đúng một nhà cung cấp: Gemini là chính; OpenAI chỉ là fallback tùy chọn nếu Gemini chưa cấu hình. OpenAI không bắt buộc khi dùng Gemini, và lỗi Gemini không tự động gửi dữ liệu sang OpenAI. Nội dung chỉ được gửi tới nhà cung cấp khi người dùng tích chọn đồng ý trên giao diện; một số thông tin liên hệ/bí mật phổ biến được che trước khi gửi.

AI được tắt mặc định (`AI_ENABLED=False`); khi tắt, không có lời gọi nhà cung cấp nào được tạo. Mặc định Gemini dùng model `gemini-3.5-flash-lite`; `gemini-2.5-flash` đã deprecated. Để bật Gemini sau này, cung cấp `GEMINI_API_KEY` cho tiến trình backend qua GitHub Codespaces Secret cùng tên, không cấu hình `OPENAI_API_KEY`, đặt `AI_ENABLED=True` chỉ trong backend development rồi khởi động lại backend. Không đưa API key vào frontend, `VITE_*`, hoặc commit file `.env`. Nếu chưa đồng ý, chưa bật AI, thiếu cấu hình hoặc nhà cung cấp lỗi/quá thời gian, API trả trạng thái `INSUFFICIENT_DATA` thay vì tạo kết quả giả. Endpoint giới hạn nội dung tối đa 12.000 ký tự, bối cảnh tối đa 4.000 ký tự và có giới hạn tổng đầu vào, timeout cùng giới hạn số yêu cầu đồng thời. Quota và billing phụ thuộc project/tier trong Google AI Studio; cần kiểm tra ở đó trước khi dùng, không thể suy ra từ việc API key tồn tại.

Giao diện yêu cầu đồng ý rõ ràng trước khi gửi tin nhắn, ảnh hoặc âm thanh đến dịch vụ AI. `POST /api/v1/scam-analysis/image` nhận raw body với `Content-Type` là `image/jpeg`, `image/png` hoặc `image/webp`, giới hạn 10 MiB và kiểm tra chữ ký tệp trước khi gửi ảnh cho Gemini Vision. `POST /api/v1/scam-analysis/audio` nhận raw body với `Content-Type` là `audio/mpeg`, `audio/wav` hoặc `audio/mp4`, giới hạn 20 MiB và kiểm tra chữ ký trước khi gửi MP3, WAV hoặc M4A cho Gemini để phiên âm tiếng Việt và phân tích. Ảnh và âm thanh chỉ được giữ tạm trong bộ nhớ, không được ghi log hoặc lưu trữ bởi ứng dụng; bản phiên âm không được trả về. Kết quả âm thanh chỉ hiện mức nguy cơ cho đến khi người dùng mở phần giải thích. Nếu Gemini chưa cấu hình hoặc không khả dụng, endpoint ảnh/âm thanh trả lỗi HTTP thay vì tạo kết quả giả. Phần phân tích văn bản tiếp tục dùng `POST /api/v1/scam-analysis`; không tự retry hoặc gửi chéo sang nhà cung cấp thứ hai. Endpoint kiểm tra URL hiện tại chỉ kiểm tra tín hiệu cơ bản, không tải website. Kết quả AI không xác minh danh tính, thương hiệu hay website; phần trăm độ tin cậy chưa được hiệu chuẩn nên không được trả về.
