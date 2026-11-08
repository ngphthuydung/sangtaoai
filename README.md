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
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

* **Trang tài liệu API tự động (Swagger UI):** Mở trình duyệt truy cập `http://127.0.0.1:8000/docs`
* **Kiểm tra trạng thái Backend:** Truy cập `http://127.0.0.1:8000/api/v1/health`

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
npm run dev
```

* Truy cập giao diện trên trình duyệt tại địa chỉ: `http://localhost:5173`
* Màn hình sẽ tự động kết nối với API Backend `http://127.0.0.1:8000/api/v1/health` và hiển thị trạng thái hoạt động trực quan.

---

## 🔒 Quy Tắc Bảo Mật Đã Thiết Lập
1. **Tuyệt đối không lưu API Key bí mật ở Frontend:** Mọi thao tác AI (OpenAI API) và Cơ sở dữ liệu bắt buộc xử lý tại Backend.
2. **Quản lý biến môi trường an toàn:** File `.env` chứa mật khẩu đã được tự động thêm vào `.gitignore` để tránh bị đẩy lên kho mã nguồn công khai.
3. **CORS:** Backend chỉ cho phép Frontend từ `http://localhost:5173` truy cập để chống tấn công giả mạo nguồn gốc.

---

## 📋 Trạng Thái Tiến Độ
* [x] **Milestone 1:** Khởi tạo khung dự án độc lập, cấu hình an toàn & API Health Check (Hoàn thành).
* [ ] **Milestone 2:** Thiết lập Cơ sở dữ liệu PostgreSQL + pgvector & Models tri thức lừa đảo.
* [ ] **Milestone 3:** Xây dựng Động cơ Phân tích AI Đa tầng (Modular Hybrid AI Engine).
* [ ] **Milestone 4:** Bộ Kiểm thử Độc lập (Evaluation Suite) với 300 - 500 mẫu tiếng Việt.
* [ ] **Milestone 5:** Giao diện Web thân thiện Người cao tuổi (Senior-Friendly UI).
* [ ] **Milestone 6:** Bộ Thu thập & Cổng Kiểm duyệt Tin tức (Collector & Moderation).
* [ ] **Milestone 7:** Cấu hình Capacitor & Đóng gói Ứng dụng Android APK.
