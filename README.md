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
│   ├── .env                       # Biến môi trường cục bộ (không commit Git)
│   └── frontend/                  # Giao diện Web Responsive (React + TypeScript + Vite)
│       ├── src/
│       │   ├── App.tsx            # Giao diện Preview V2
│       │   ├── main.tsx           # Điểm khởi chạy của React
│       │   └── index.css          # Kiểu giao diện responsive và truy cập được
│       ├── package.json           # Danh mục thư viện Frontend
│       ├── .env.example           # Mẫu cấu hình URL Backend cho Frontend
│       └── .env                  # Cấu hình cục bộ (không commit Git)
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
cd backend/frontend

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

AI được tắt mặc định (`AI_ENABLED=False`); khi tắt, không có lời gọi nhà cung cấp nào được tạo. Mặc định Gemini dùng model `gemini-3.5-flash-lite`; `gemini-2.5-flash` đã deprecated. Để bật Gemini, cung cấp `GEMINI_API_KEY` cho tiến trình backend qua secret của môi trường triển khai; không cấu hình `OPENAI_API_KEY` nếu không chủ động dùng OpenAI. Không đưa API key vào frontend, `VITE_*`, hoặc commit file `.env`. Khi chưa đồng ý, API trả `analysis_status=NOT_ANALYZED`. Khi AI chưa được cấu hình hoặc gặp lỗi/quá thời gian, API không tạo kết quả giả: phản hồi văn bản có `analysis_status=FAILED` và `risk_level=INSUFFICIENT_DATA`; frontend hiển thị lỗi dịch vụ riêng, không coi đó là kết luận phân tích.

Backend tự động thử lại tối đa một lần khi gặp lỗi provider tạm thời được phân loại; lỗi cấu trúc phản hồi, lỗi xác thực và phản hồi 429 do quota/rate limit không được tự động thử lại. Ngân sách thời gian cho các lần gọi provider tối đa 55 giây. Frontend không tự gửi lại yêu cầu sau lỗi mạng/gateway vì không thể xác định chắc chắn backend đã xử lý request hay chưa. Nếu dịch vụ vẫn không phản hồi, người dùng có thể thử lại thủ công trên cùng trang với nội dung đã nhập được giữ nguyên. Giới hạn nội dung, timeout và số yêu cầu đồng thời được cấu hình qua biến môi trường backend. Quota và billing phụ thuộc project/tier trong Google AI Studio.

Giao diện yêu cầu đồng ý rõ ràng trước khi gửi tin nhắn, ảnh hoặc âm thanh đến dịch vụ AI. `POST /api/v1/scam-analysis/image` nhận raw body với `Content-Type` là `image/jpeg`, `image/png` hoặc `image/webp`, giới hạn 10 MiB và kiểm tra chữ ký tệp trước khi gửi ảnh cho Gemini Vision. `POST /api/v1/scam-analysis/audio` nhận raw body với `Content-Type` là `audio/mpeg`, `audio/wav` hoặc `audio/mp4`, giới hạn 20 MiB và kiểm tra chữ ký trước khi gửi MP3, WAV hoặc M4A cho Gemini để phiên âm tiếng Việt và phân tích. Ảnh và âm thanh chỉ được giữ tạm trong bộ nhớ, không được ghi log hoặc lưu trữ bởi ứng dụng; bản phiên âm không được trả về. Nếu Gemini chưa cấu hình hoặc không khả dụng, endpoint ảnh/âm thanh báo lỗi dịch vụ thay vì tạo kết quả giả. Phần phân tích văn bản tiếp tục dùng `POST /api/v1/scam-analysis`; không gửi chéo sang nhà cung cấp thứ hai. Endpoint kiểm tra URL hiện tại chỉ kiểm tra tín hiệu cơ bản, không tải website. Kết quả AI không xác minh danh tính, thương hiệu hay website; phần trăm độ tin cậy chưa được hiệu chuẩn nên không được trả về.

Repository hiện không có `render.yaml`, Dockerfile hoặc thiết lập triển khai Render được kiểm soát phiên bản. Vì vậy, chưa thể xác nhận cấu hình cold start, health-check path, start command, sleep/instance plan hoặc giới hạn request của dịch vụ Render đang chạy; cần kiểm tra trực tiếp trong Render Dashboard. Health check API là `GET /api/v1/health`; trường `revision` chỉ trả SHA 40 ký tự hợp lệ từ `RENDER_GIT_COMMIT`, nếu biến này có sẵn, nếu không trả `null`. Frontend chờ tối đa 70 giây; timeout của gateway bên ngoài cần dài hơn mức này hoặc được điều chỉnh đồng bộ trong cấu hình triển khai.

## Preview V3: media, chẩn đoán và xử lý theo lô

- Màn hình chính giữ bốn lựa chọn Tin nhắn, Đường link, Hình ảnh và Âm thanh; chỉ hiện vùng nhập đang chọn. Kết quả mặc định chỉ hiện mức độ và hành động tiếp theo. Bằng chứng, dấu hiệu, nội dung chưa xác minh và giới hạn nằm trong một mục mở rộng. Lỗi dịch vụ không được đổi thành kết luận an toàn.
- Có thể chọn tối đa 5 ảnh hoặc 5 tệp âm thanh (tổng tối đa theo giới hạn từng loại là 50 MiB ảnh hoặc 100 MiB âm thanh). Mỗi tệp được kiểm tra và gửi riêng, tuần tự; tệp hợp lệ vẫn được phân tích khi tệp khác lỗi. Có thể thử lại riêng từng tệp lỗi; kết quả đã thành công được giữ nguyên. Batch giới hạn 5 tệp hiện ở frontend; backend chỉ cung cấp endpoint một tệp mỗi request.
- Giới hạn đang áp dụng: ảnh tối đa 10 MiB và 20 megapixel; âm thanh tối đa 20 MiB mỗi tệp. Trình duyệt kiểm tra chữ ký cơ bản; backend giải mã ảnh, kiểm tra khung MP3, cấu trúc WAV PCM và chữ ký container M4A trước khi gọi Gemini. MP3/M4A chưa được giải mã hoàn chỉnh; thời lượng cũng chưa được kiểm tra/giới hạn. Các giới hạn này là giới hạn ứng dụng, không phải giới hạn xác nhận cho mọi gói Gemini hay cấu hình Render.
- Dữ liệu ảnh/âm thanh được giữ trong bộ nhớ của request, không ghi vào ổ đĩa ứng dụng và không ghi nội dung vào log. Gemini hiện nhận media qua `inlineData`; Base64 làm tăng kích thước yêu cầu khoảng một phần ba (20 MiB âm thanh thành khoảng 26.7 MiB, chưa tính prompt). Tài liệu Gemini hiện khuyến nghị Files API khi tổng request vượt 100 MB; quota, model đang cấu hình và xử lý từng file production vẫn cần xác minh trong Google AI Studio. Xem [Gemini Files API](https://ai.google.dev/gemini-api/docs/files).
- Mỗi yêu cầu phân tích có `X-Request-ID`, stage, loại lỗi, HTTP status, thời lượng, số lần thử lại và (nếu có) status của provider. Backend ghi một log JSON chỉ chứa metadata định danh request/route; không ghi nội dung, transcript, ảnh, âm thanh hoặc API key. Frontend hiện mã hỗ trợ và metadata để hỗ trợ điều tra. Thông tin này chưa đủ để quy nguyên nhân cho các file IMG_2096.jpeg hoặc TEST_03_giao_hang_dang_ngo.mp3 nếu thiếu request ID và log production tương ứng.
- Retry tự động chỉ ở backend: tối đa một lần gọi Gemini bổ sung cho lỗi kết nối/timeout kết nối hoặc HTTP upstream 408, 425, 500, 502, 503. Không retry lỗi đọc/ghi timeout không chắc chắn, lỗi xác thực, 429, response sai cấu trúc hoặc HTTP 504. Frontend không gửi lại tự động; người dùng tự chọn nút thử lại sau lỗi. Điều này tránh chồng retry giữa hai tầng.

### Giới hạn hạ tầng và production evidence

Không có cấu hình Render được commit và không có quyền truy cập vào Render Dashboard, logs hoặc Google AI Studio của deployment đang chạy. Do đó chưa thể xác nhận body limit/gateway timeout thực tế, loại instance, cold start hiện hành, Gemini model/key/quota hoặc thất bại cụ thể của hai tệp được nêu. Nếu dùng Render Free, tài liệu Render ghi service có thể spin down sau 15 phút và mất khoảng một phút để khởi động lại; filesystem là ephemeral. Đây chỉ là giới hạn của gói Free, không phải bằng chứng rằng production đang dùng gói đó. Xem [Render Free instances](https://render.com/docs/free) và kiểm tra dashboard trước khi deploy.

Để xác định lỗi production, cần đối chiếu request ID với bản ghi log metadata; HTTP status/stage/category/provider status/retry/duration; cấu hình timeout, instance và deploy của Render; Gemini model/quota cùng redacted provider error. Chỉ thu thập metadata media không nhạy cảm (kích thước byte, MIME khai báo và phát hiện, định dạng/codec, kích thước ảnh hoặc thời lượng nếu xác định được); không gửi media, transcript, message hay API key vào log.

### Đích kiến trúc batch 500 MB (chưa triển khai)

Không tăng giới hạn request hiện tại lên 500 MB. Trước khi hỗ trợ batch tổng 500 MB, cần có luồng tải lên theo từng phần có thể tiếp tục: backend tạo upload/job ID có xác thực và URL ký hạn ngắn; client tải từng chunk trực tiếp tới object storage có lifecycle TTL; backend xác minh checksum/loại tệp; queue bền vững đưa từng file tới worker; API trạng thái job theo dõi tiến độ/kết quả từng file và retry độc lập. Worker tải file theo streaming hoặc dùng Gemini Files API, giới hạn concurrency/token/cost theo người dùng, xóa object và dữ liệu tạm tự động sau thời hạn, đồng thời giới hạn tốc độ, tổng byte, số job và chi phí.

Render có thể lưu trữ web service, background worker và cơ sở dữ liệu/queue phù hợp với plan; object storage riêng vẫn cần chọn và cấu hình. Không nên giữ batch lớn trong RAM, gửi một request khổng lồ, hoặc dùng filesystem ephemeral làm nơi lưu bền vững. Cần đo RAM/disk/timeouts theo plan thực tế, chọn object storage/queue, authentication, thời hạn lưu và mức chi phí rồi mới xin duyệt triển khai. Không tạo hạ tầng tính phí trong Preview V3.

### Khả năng ứng dụng di động trong tương lai

Frontend vẫn dựa trên React/Vite và Capacitor; hiện package có `@capacitor/core` và `@capacitor/android`, chưa có `@capacitor/ios` hoặc plugin camera/microphone/share. Preview V3 không thay đổi dự án native. App native sau này có thể xin quyền truy cập ảnh/camera, micro, chia sẻ nội dung từ app khác và thông báo qua plugin/native code, kèm giải thích mục đích và đồng ý rõ ràng. Quyền thực tế tùy phiên bản hệ điều hành, quyền người dùng và chính sách cửa hàng. Android/iOS đều giới hạn chạy nền; iOS đặc biệt không cho ứng dụng bên thứ ba tùy ý đọc cuộc gọi/tin nhắn hoặc chạy nền liên tục. Không thể hứa bảo vệ mọi cuộc gọi, SMS hay hoạt động của ứng dụng khác. APK/iOS release cần kiểm tra quyền, privacy manifest/chính sách, ký ứng dụng và kiểm thử thiết bị thật; chưa sẵn sàng phát hành chỉ từ bản web preview.

## Preview V4: reasoning, media và evaluation

- Nguyên nhân trong mã cũ: kết quả rủi ro chủ yếu theo nhãn do Gemini trả về; tầng bằng chứng chỉ so khớp trích dẫn nguyên văn, nên trích dẫn khác khoảng trắng/dòng mới bị loại và cả nhận định rủi ro cao có thể trở thành “chưa đủ bằng chứng”. Gemini cũng được hướng dẫn thận trọng nhưng chưa có tiêu chí rõ để chọn `SUSPICIOUS` thay vì `INSUFFICIENT_DATA`.
- V4 chuẩn hóa khoảng trắng khi đối chiếu trích dẫn nhưng trả về đúng đoạn gốc (không tự viết lại câu). Phân loại được suy ra từ các hành vi mà trích dẫn khớp: yêu cầu OTP/mật khẩu hoặc tổ hợp giả danh cơ quan + chuyển tiền + đe dọa/ép buộc có thể là nguy cơ cao; dấu hiệu đơn lẻ có căn cứ là đáng ngờ. Không có trích dẫn hợp lệ thì không đưa kết luận nguy cơ cao/đáng ngờ. “Chưa thấy dấu hiệu rõ ràng” luôn kèm cảnh báo không đồng nghĩa an toàn.
- Prompt Gemini nay bao quát giả mạo ngân hàng/cơ quan/giao hàng, phí giao hàng, OTP/mật khẩu, đầu tư/tuyển dụng, giải thưởng, link, chuyển tiền, đe dọa/khẩn cấp và đọc hội thoại nhiều tin nhắn. Ảnh yêu cầu giữ thứ tự chữ, người gửi và bong bóng hội thoại; tăng đầu ra tối đa riêng cho ảnh từ mức mặc định 1.200 lên 2.400 token để có thêm chỗ cho OCR, không đổi giới hạn upload. Điều này có thể làm tăng chi phí khi ảnh cần OCR dài; cần theo dõi lượng token thực tế. Âm thanh báo trạng thái phiên âm `COMPLETED`, `PARTIAL` hoặc `FAILED`; phiên âm thất bại không bị nhầm với kết quả thiếu bằng chứng sau phân tích. API chỉ thêm trường tùy chọn `transcription_status`, không trả transcript.
- Mỗi kết luận trên màn hình chính có giải thích ngắn; trích dẫn và mức đủ bằng chứng nằm trong “Xem giải thích chi tiết”. Trích dẫn hiển thị sau khi hệ thống đã che thông tin liên hệ/bí mật phổ biến nếu phát hiện.
- Có kiểm thử provider giả lập cho tin nhắn giả ngân hàng/OTP, phí giao hàng, thông báo ngân hàng thông thường, thông báo mơ hồ, giả danh cơ quan kèm chuyển tiền/đe dọa, lời hứa đầu tư, trích dẫn không hợp lệ, audio không nghe rõ và response Gemini chưa hoàn tất. Mẫu đánh giá là regression giả lập, không phải dữ liệu đo hiệu năng Gemini.
- Bộ đo ngoại tuyến nhận JSONL gồm `case_id`, nhãn chuẩn `expected` (`SCAM`/`NOT_SCAM`) và `predicted` (`HIGH_RISK`/`SUSPICIOUS`/`LOW_RISK`/`INSUFFICIENT_DATA`). Chạy bằng `cd backend && python -m app.evaluation du-doan.jsonl`. Báo cáo precision, recall, false-negative rate và confusion matrix; `INSUFFICIENT_DATA` của mẫu lừa đảo được tính là bỏ sót để tránh che khuất rủi ro. Không có bộ dữ liệu gán nhãn thực trong repo nên không công bố độ chính xác/precision/recall của Gemini. Không đưa nội dung người dùng vào file đánh giá chia sẻ; chỉ lưu mã mẫu và nhãn.
- Nhiều ảnh vẫn được gửi phân tích riêng theo thứ tự người dùng chọn; hiện chưa nối OCR của ảnh trước làm ngữ cảnh cho ảnh sau. Muốn đánh giá trọn hội thoại qua nhiều ảnh cần thiết kế API/luồng riêng và kiểm tra giới hạn truyền tải trước khi triển khai.

## Preview V5: phân loại thận trọng và kết quả có căn cứ

- Điểm yếu đã xác nhận trong mã V4: tầng hợp nhất có thể tự nâng finding đã trích dẫn thành `SUSPICIOUS`, kể cả khi mô hình đánh giá `INSUFFICIENT_DATA`; một ảnh không đọc được chữ vẫn có thể nhận `LOW_RISK` nếu mô hình trả về nhãn đó. Đây là lỗi chính sách trong mã, không phải kết luận về một sự cố production cụ thể.
- V5 yêu cầu trích dẫn được kiểm chứng và xem xét ngữ cảnh. Finding hợp lệ không tự nâng `INSUFFICIENT_DATA`; nếu nhãn mô hình là `LOW_RISK`, chỉ trích dẫn thuộc nhóm lấy OTP/mật khẩu rõ ràng hoặc tổ hợp giả danh–chuyển tiền–đe dọa/ép buộc mới nâng tối thiểu lên `SUSPICIOUS`, không tự kết luận `HIGH_RISK`. `HIGH_RISK` cần cả nhãn nguy cơ cao của mô hình lẫn bằng chứng thuộc nhóm hành vi nguy hiểm đã quy định. Ảnh/âm thanh chỉ đọc được một phần không thể trả `HIGH_RISK`; nếu thiếu trạng thái đọc/phiên âm, nội dung được xem là một phần thay vì mặc định hoàn tất. Ảnh không đọc được chữ trả `INSUFFICIENT_DATA`, không phải kết luận an toàn.
- Prompt nhấn mạnh phân biệt lời cảnh báo OTP với yêu cầu lấy OTP, xét phủ định, bối cảnh giao dịch và toàn bộ hội thoại. Trích dẫn không hợp lệ tiếp tục bị loại. Tên/mô tả hành vi chưa có trong danh mục không còn hiển thị nguyên văn từ mô hình; khuyến nghị và thông tin chưa xác minh dùng nội dung tiếng Việt cố định, ngắn và an toàn.
- Bộ kiểm thử provider giả lập bao gồm nội dung hợp lệ, các tình huống đáng ngờ/nguy cơ cao, dữ liệu thiếu, kết quả mâu thuẫn, OCR không đọc được/một phần và giữ nguyên trích dẫn. Đây là kiểm thử logic với response giả, không phải đánh giá Gemini thật.
- Bộ `app.evaluation` vẫn đo precision, recall, false-negative rate và confusion matrix từ nhãn chuẩn `SCAM`/`NOT_SCAM`; các dự đoán `HIGH_RISK`, `SUSPICIOUS`, `LOW_RISK` và `INSUFFICIENT_DATA` được quy về phát hiện, không phát hiện hoặc chưa phân loại. Không có nhãn thực đại diện trong repository; không thể dùng các ca giả lập để tuyên bố độ chính xác của Gemini.
- Chưa có kiểm thử Gemini/Render production, tập dữ liệu thực đại diện hoặc luồng gộp ngữ cảnh qua nhiều ảnh. Cần đánh giá với dữ liệu đã gán nhãn, có sự cho phép và bảo vệ riêng tư, trước khi phát hành rộng.
