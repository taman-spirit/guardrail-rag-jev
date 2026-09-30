# Kiến trúc guardrail-rag-jev

**Tiếng Việt** · Tài liệu này mô tả vì sao guardrail được thiết kế như hiện nay, dựa trên khảo sát
nhu cầu của các hệ thống RAG ([rag-integration-research.vi.md](rag-integration-research.vi.md)) và
các sản phẩm cùng loại ([market-research.vi.md](market-research.vi.md)).

> Đây là tài liệu kỹ thuật, không phải tư vấn pháp lý. Mọi ánh xạ tới văn bản luật cần được bộ phận
> pháp chế đối chiếu trước khi vận hành.

---

## 1. Bài toán

Một hệ thống RAG có bốn điểm mà nội dung đi qua. Mỗi điểm có rủi ro riêng:

| Điểm | Nội dung | Rủi ro chính | Ai chờ kết quả |
| --- | --- | --- | --- |
| `ingest` | chunk tài liệu trước khi đưa vào vector store | chỉ thị ẩn (prompt injection gián tiếp), đầu độc dữ liệu, dữ liệu cá nhân, bí mật, nội dung vi phạm pháp luật | pipeline index, không phải người dùng |
| `query` | câu hỏi của người dùng | jailbreak, yêu cầu nội dung cấm, dữ liệu cá nhân trong câu hỏi | người dùng |
| `context` | các đoạn truy xuất trước khi đưa vào LLM | chỉ thị ẩn trong tài liệu cũ hoặc nguồn ngoài, dữ liệu cá nhân, đoạn không liên quan, truy xuất vượt quyền | người dùng |
| `answer` | câu trả lời được sinh ra | bịa đặt so với nguồn, lộ dữ liệu, vi phạm pháp luật, AI tự nhận là người | người dùng |

Ở mỗi điểm, guardrail trả lời hai câu hỏi tách biệt:

1. **Có vi phạm gì?** Kết quả là danh sách *tất cả* vi phạm. Mỗi vi phạm có nhóm, căn cứ (luật hoặc chuẩn), mức độ, xác suất và vị trí trong văn bản nếu xác định được.
2. **Làm gì với nội dung?** Kết quả là một trong bốn quyết định: `pass` (dùng), `redact` (che rồi dùng), `review` (giữ lại chờ người duyệt), `remove` (loại bỏ).

## 2. Tổng quan kiến trúc

```
                    ┌──────────────────────── guardrail-rag-jev ────────────────────────┐
 ứng dụng RAG       │                                                                   │
 (LangChain,        │  API / SDK        Enforcement          Decision engine            │
  LlamaIndex, Dify, │  ─────────        ───────────          ───────────────            │
  Go/Python, ...)   │  /v1/ingest ─┐                                                    │
        │           │  /v1/query  ─┼─▶ profile ─▶ detectors ─▶ cache ─▶ policy ─▶ questions
        ▼           │  /v1/context─┤    (tenant/app)  (PII, secret,        (base +       │
   HTTP / SDK ─────▶│  /v1/answer ─┤                   ký tự ẩn, ACL)      gói luật)     │
                    │  /v1/jobs   ─┘                                          │         │
                    │  Dify, Azure skill                                      ▼         │
                    │                              ┌────────── Provider layer ────────┐ │
                    │                              │ Normalizing ─▶ Jev (mặc định)     │ │
                    │                              │             ─▶ OpenAI Decisions   │ │
                    │                              │             ─▶ LLM-judge (vLLM,   │ │
                    │                              │                Ollama, GreenNode) │ │
                    │                              │             ─▶ plugin             │ │
                    │                              │ Fallback · Shadow · Residency     │ │
                    │                              └───────────────────────────────────┘ │
                    │                                                         │         │
                    │  decide() ─▶ verdict ─▶ decision ─▶ Result (violations, content)  │
                    │                              │                                    │
                    │               ┌──────────────┼───────────────┐                    │
                    │               ▼              ▼               ▼                    │
                    │         Review queue    Audit log       Metrics (Prometheus)      │
                    │         (override theo  (chuỗi băm,     (/metrics)                │
                    │          hash nội dung)  SIEM webhook)                            │
                    └───────────────────────────────────────────────────────────────────┘
```

Các lớp:

| Lớp | Module | Trách nhiệm |
| --- | --- | --- |
| Policy | `policy.py`, `policies/` | Taxonomy chuẩn cho RAG và các gói luật ghép lên. Bật/tắt gói, tắt từng nhóm, đổi ngưỡng, khoá mức tối thiểu |
| Questions | `questions.py` | Chuyển policy thành bộ câu hỏi chuẩn: chọn-một, có/không cho từng nhóm (multi-label), thang điểm |
| Providers | `providers/` | Model trả lời bộ câu hỏi. Model có thể thay mà không phải sửa policy hay engine |
| Engine | `decide.py` | Chuyển câu trả lời thành verdict. Không gọi mạng, không giữ trạng thái, kiểm thử được hoàn toàn offline |
| Detectors | `detectors.py` | Tìm chính xác vị trí dữ liệu cá nhân Việt Nam, bí mật và ký tự ẩn. Dùng để che, defang URL, và cho các pattern allow/deny của khách hàng |
| Enforcement | `guard.py` | Verdict cộng cấu hình enforcement ra quyết định. Định vị vi phạm, gom kết quả theo tài liệu, cache, shadow |
| Review | `review.py` | Hàng đợi duyệt. Quyết định của người duyệt được ghi thành override theo hash nội dung, nên lần sau gặp lại không cần hỏi model |
| Audit | `audit.py` | Log chuỗi băm có hàm `verify()`. Mặc định chỉ lưu nội dung đã che, và có webhook sang SIEM |
| Service | `server.py` | FastAPI: 4 điểm kiểm tra, batch, job bất đồng bộ, review, audit, policy runtime, Dify, Azure WebApiSkill, metrics |
| Clients | `clients/go`, `integrations/` | Go client, LangChain, LlamaIndex |

## 3. Quyết định kiến trúc

### 3.1. Model quyết định có thể thay thế

**Bối cảnh.** Hiện có TypeSafe Jev: một decision model, gộp nhiều câu hỏi trong một request, trả xác
suất đã hiệu chỉnh, độ trễ 70-500 ms. OpenAI vừa công bố Decisions API chạy trên GPT-6 Luna. API này
đang ở preview giới hạn và chưa công bố schema, định dạng confidence hay giá. Ngoài ra, thị trường
Việt Nam cần judge chạy nội bộ vì lý do dữ liệu (xem 3.2).

**Quyết định.** Engine chỉ nói một "giao thức quyết định" chuẩn. Mỗi model là một adapter.

- **Câu hỏi** có ba loại: `choice` (chọn một nhãn, kèm phân phối xác suất), `noul` (xác suất một mệnh đề đúng) và `score` (thang thứ bậc).
- **Câu trả lời** có cùng hình dạng, bất kể model nào sinh ra.
- **`Capabilities`** khai báo những gì model làm được natively. Lớp `Normalizing` bù phần thiếu:

| Model không có | Normalizing làm |
| --- | --- |
| gộp nhiều câu hỏi | tách từng câu, gọi song song |
| câu hỏi có/không | hỏi thành `choice` hai nhãn `yes` / `no` |
| câu hỏi thang điểm | hỏi thành `choice` trên các mức, đọc lại bằng giá trị kỳ vọng |
| xác suất từng nhãn | nhãn được chọn nhận confidence, phần còn lại chia đều |

| Provider | Trạng thái | Ghi chú |
| --- | --- | --- |
| `jev` | mặc định | Native, không cần chuẩn hoá |
| `openai-decisions` | thử nghiệm | Endpoint và tên trường cấu hình được, để khi OpenAI công bố schema chỉ cần đổi config |
| `llm-judge` | ổn định | Mọi model có API tương thích OpenAI: OpenAI, Azure, vLLM, Ollama, NIM, GreenNode MaaS, Vistral/SeaLLM tự host |
| `offline` | demo | Heuristic từ khoá, không dùng cho nội dung thật |
| `fallback` | ổn định | Chuỗi provider; provider đầu tiên trả lời được thì dùng |
| `plugin` | mở rộng | `module:Class` của bạn, ví dụ Llama Guard, Granite Guardian, SEA-Guard |

**Hiệu chỉnh theo model.** Ngưỡng trong policy được hiệu chỉnh cho một model cụ thể. Khi đổi model,
nạp *calibration overlay* của model đó (một policy patch, cùng cơ chế với gói luật) qua
`providers.<name>.calibration`. Không dùng lại ngưỡng của model khác.

**Chuyển model an toàn.** Dùng `shadow`: model chính ra quyết định, model thứ hai trả lời cùng bộ
câu hỏi ở chế độ nền. Mỗi lần hai model quyết định khác nhau, audit ghi một bản ghi
`shadow.compare`. Chạy shadow trên traffic thật cho đến khi tỷ lệ bất đồng chấp nhận được, rồi mới
đổi `provider`.

### 3.2. Nơi dữ liệu đi qua (residency)

**Bối cảnh.** Luật Bảo vệ dữ liệu cá nhân (Luật số 91/2025/QH15) và Nghị định 356/2025/NĐ-CP coi việc
xử lý dữ liệu cá nhân trên hạ tầng ở nước ngoài là chuyển dữ liệu xuyên biên giới, kèm nghĩa vụ đánh
giá tác động. Gửi nội dung tài liệu tới một judge đặt ở nước ngoài cũng thuộc trường hợp này. Doanh
nghiệp và cơ quan Việt Nam (MISA, Viettel, VNPT...) có xu hướng chạy AI on-prem hoặc trên cloud
trong nước.

**Quyết định.** Mỗi provider khai báo `residency`: `offshore`, `vn_hosted` hoặc `local`. Config có
`residency.allow`. Guard từ chối khởi động nếu một provider không được phép, kể cả provider nằm
trong chuỗi fallback hay shadow. Bộ triển khai Docker hỗ trợ chạy hoàn toàn nội bộ với `llm-judge`
trỏ tới vLLM hoặc Ollama.

### 3.3. Bốn điểm kiểm tra, bốn cách xử lý review

Mỗi điểm có ngân sách độ trễ và cách xử lý "cần xem xét" khác nhau:

| Điểm | Chế độ | `review` nghĩa là | Khi Jev không phản hồi |
| --- | --- | --- | --- |
| `ingest` | đồng bộ hoặc job bất đồng bộ | `hold`: cách ly, chưa index, chờ duyệt | `fail_closed`: cách ly, xếp hàng |
| `query` | đồng bộ | `hold`: trả câu trả lời viết sẵn | `fail_open`: model phía sau vẫn có lớp an toàn riêng |
| `context` | đồng bộ, song song các chunk | `remove`: bỏ chunk ngay, vẫn xếp hàng duyệt | `fail_open` |
| `answer` | đồng bộ | `hold`: trả thông báo đang xem xét | `fail_closed`: lớp cuối cùng |

Tất cả đều cấu hình được. Chế độ `shadow` của enforcement chỉ ghi lại "lẽ ra đã làm gì" và cho mọi
nội dung đi qua. Dùng chế độ này cho giai đoạn chạy thử trước khi bật thật.

### 3.4. Nhiều vi phạm trong một nội dung

Câu hỏi chọn-một chỉ chỉ ra vi phạm nặng nhất. Guardrail phát hiện đủ mọi vi phạm bằng ba cách:

1. **Multi-label.** Ngoài câu hỏi chọn-một, mỗi nhóm có một câu hỏi có/không riêng. Jev trả lời mọi câu hỏi song song và không tính phí token đầu ra, nên chi phí tăng thêm chỉ là token đầu vào. Mặc định bật cho `ingest`, `context` và `answer`.
2. **Định vị.** Khi một tài liệu dài có vi phạm, guardrail tách nó thành các đoạn và hỏi lại riêng các nhóm đã phát hiện, để chỉ ra đoạn nào vi phạm nhóm nào kèm vị trí ký tự. Mặc định bật cho `ingest`.
3. **Detector.** Detector cho vị trí chính xác của dữ liệu cá nhân, bí mật và ký tự ẩn.

Mỗi `Result` trả về `violations`, liệt kê đủ tất cả vi phạm.

### 3.5. Tái sử dụng kết quả và idempotency

- Kết quả được cache theo khoá `sha256(nội dung) + fingerprint của policy + provider`. Khi policy đổi, fingerprint đổi, nên cache cũ tự hết hiệu lực.
- Chunk đã kiểm lúc `ingest` sẽ được dùng lại ở `context` nếu policy và provider chưa đổi. Hầu hết đoạn truy xuất đều đã được kiểm khi index.
- Quyết định của người duyệt trở thành override theo hash nội dung, với phạm vi `document` (dùng chung cho ingest và context), `query` hoặc `answer`. Lần sau gặp đúng nội dung đó thì không hỏi model nữa.
- Mỗi kết quả `ingest` trả `metadata` gồm `guard_decision`, `guard_policy` và `guard_checked_at`, để ghi ngược vào vector store và lọc khi truy xuất.

### 3.6. Audit là bằng chứng

- Mỗi bản ghi chứa hash của bản trước. `verify()` chỉ ra chính xác bản ghi bị sửa, xoá hay đảo thứ tự.
- Audit log cũng là nơi lưu dữ liệu cá nhân, nên mặc định chỉ lưu nội dung đã che (`store_content: redacted`). Các mức khác gồm `hash`, `none` và `full`.
- Mọi sự kiện đều được ghi: `check`, `review.created`, `review.decided`, `policy.changed`, `shadow.compare`, `job.*`.
- Bản ghi có thể forward sang SIEM qua webhook. Nên lưu `head()` ở nơi mà tiến trình ghi log không sửa được.

### 3.7. Đa tenant

Mỗi request có thể mang `profile`. Profile là một phần config ghi đè lên config gốc: gói luật,
ngưỡng, enforcement, provider và residency. Nhờ đó một tenant ngân hàng có thể bật mọi gói luật và
dùng judge nội bộ, trong khi một app marketing dùng Jev. `tenant` và `profile` được ghi vào audit
và hàng đợi review để lọc riêng theo từng tenant.

### 3.8. Không tự làm việc của retriever

Phân quyền truy xuất (ACL) thuộc về retriever. Guardrail chỉ **kiểm tra chéo**: ở điểm `context`, nếu
chunk có `acl` và request có `principals`, một chunk nằm ngoài quyền của người hỏi sẽ bị loại và ghi
nhận là vi phạm `acl` (OWASP LLM08). Đây là lớp phòng thủ thứ hai, không thay cho lọc ở retriever.

## 4. Luồng tích hợp

| Nền tảng | Ingest | Context | Query / Answer | Cách tích hợp |
| --- | --- | --- | --- | --- |
| Python (tự viết) | `guard.check_document` | `guard.filter_context` | `guard.check_query` / `check_answer` | thư viện |
| Go (tự viết) | `CheckDocuments` | `FilterContext` | `CheckQuery` / `CheckAnswer` | `clients/go` qua HTTP |
| LangChain | `GuardrailDocumentTransformer` | `GuardedRetriever` | `guard_runnable` | `integrations/langchain.py` |
| LlamaIndex | `GuardrailTransform` | `GuardrailPostprocessor` | `guard.check_query` / `check_answer` quanh query engine | `integrations/llamaindex.py` |
| Dify | gọi `/v1/ingest` trước khi upload | node HTTP | moderation API extension | `POST /v1/integrations/dify/moderation` |
| Azure AI Search | custom WebApiSkill | wrapper | - | `POST /v1/integrations/azure/skill` |
| AWS Bedrock KB | Lambda `POST_CHUNKING` | `Retrieve` rồi `/v1/context` | - | `examples/integrations/bedrock_lambda.py` |
| Open WebUI | - | filter `inlet` | filter `inlet` / `outlet` | `examples/integrations/openwebui_filter.py` |
| Nền tảng đóng (OpenAI file search, Vertex) | chặn trước khi upload | - | gateway | HTTP |

## 5. Hiệu năng

Mục tiêu với Jev: p50 ≤ 150 ms và p95 ≤ 400 ms cộng thêm cho `query` và `context`.

- **`query`** chạy song song với truy xuất.
- **`context`** kiểm top-k sau rerank (5-20 chunk) song song, dùng lại kết quả của lúc ingest.
- **`answer`** là lần kiểm duy nhất nằm trên đường đi đến người dùng sau khi sinh. Khi streaming, dùng `partial=True` cho các đoạn giữa chừng (chỉ hỏi nhóm sentinel), và kiểm đầy đủ khi câu trả lời hoàn tất.
- **`ingest`** bị giới hạn bởi bước parse tài liệu (0,5-3 s/trang), không phải bởi guardrail. Dùng job bất đồng bộ, cache theo hash, và micro-batch theo giới hạn tốc độ của provider (`concurrency`).

## 6. Những gì chưa làm

- Adapter chính thức cho Llama Guard 4, Granite Guardian và SEA-Guard. Có thể thêm ngay qua `plugin`.
- Streaming qua SSE với tín hiệu rút lại (retract).
- Job queue phân tán (Redis/Kafka). Hiện tại job chạy trong tiến trình và được lưu bằng SQLite.
- Tracing OpenTelemetry. Hiện tại có metrics Prometheus và audit log.
- Đăng nhập SSO cho người duyệt và duyệt hai người (four-eyes). Hiện tại phân quyền theo API key và tenant.
- Connector purge cho từng vector store (pgvector, Milvus, Qdrant...). Hiện tại chỉ trả `metadata` để ghi ngược vào vector store.
- Bộ dữ liệu có nhãn tiếng Việt để hiệu chỉnh ngưỡng theo từng provider.
