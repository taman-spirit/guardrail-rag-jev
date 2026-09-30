# Nghiên cứu nhu cầu tích hợp của hệ thống RAG

*Cập nhật 30/09/2026.* Hệ thống RAG thực tế cần gì từ một guardrail, và guardrail cắm vào các nền
tảng phổ biến ở đâu. Kết luận của tài liệu này là căn cứ cho [architecture.vi.md](architecture.vi.md).

## 1. Guardrail cắm vào đâu

| Nền tảng | Ingest | Context | Query / Answer | Hình thức |
| --- | --- | --- | --- | --- |
| LangChain / LangGraph | document transformer | bọc retriever | middleware `before_model` / `after_model` | Python SDK |
| LlamaIndex | `TransformComponent` trong `IngestionPipeline` | node postprocessor | workflow, query engine | Python SDK |
| Haystack 2.x | component trong indexing pipeline | component giữa retriever và prompt | `LLMMessagesRouter` | Python SDK |
| Dify | không có; kiểm trước khi upload | node HTTP | **moderation API extension** (webhook) | HTTP |
| RAGFlow | Ingestion Pipeline | component agent | component agent | HTTP |
| n8n / Flowise | node | node | node Guardrails | HTTP |
| Open WebUI | không thực tế | filter `inlet` | filter `inlet` / `outlet` | filter Python gọi HTTP |
| Spring AI | `DocumentTransformer` | `DocumentPostProcessor` | Advisor | Java gọi HTTP |
| AWS Bedrock KB | **Lambda `POST_CHUNKING`** | `Retrieve` rồi tự kiểm | Bedrock Guardrails | Lambda gọi HTTP |
| Azure AI Search | **custom WebApiSkill** | bọc lời gọi truy vấn | Content Safety | HTTP theo hợp đồng cố định |
| Vertex AI RAG Engine | kiểm trước khi upload | bọc lời gọi retrieval | Model Armor | HTTP |
| OpenAI file search | kiểm trước khi upload | endpoint search rồi tự kiểm | gateway | proxy |

**Kết luận.**
- **Ingest:** chỉ cắm trực tiếp được vào các framework code, Bedrock (Lambda), Azure (WebApiSkill) và RAGFlow. Các nền tảng còn lại cần chặn *trước khi upload*.
- **Context:** API "retrieve-and-generate" được quản lý hoàn toàn thì che mất context. Muốn kiểm context phải tách thành hai bước truy xuất rồi sinh.
- **Query và answer:** cắm được ở mọi nơi, qua webhook hoặc gateway.

## 2. Thực tế của bước ingest

- **Chi phí nằm ở bước parse tài liệu, không ở guardrail.** Docling trên CPU mất trung vị khoảng 0,8 s/trang; OCR thêm khoảng 1,6 s/trang. Vì vậy guardrail nhận **văn bản đã parse kèm metadata**, không nhận file thô.
- **Thông lượng.** Cần xử lý hàng trăm đến hàng nghìn chunk mỗi giây theo batch (Azure gửi tới 1.000 bản ghi mỗi lần gọi). Do đó cần gộp nhiều câu hỏi trong một lần gọi, cache theo hash nội dung, và job bất đồng bộ.
- **Độ chi tiết.** Quyết định ở mức chunk, rồi gom thành quyết định cho cả tài liệu. Giữ `doc_id`, `chunk_id`, vị trí ký tự và nguồn để truy ngược về tài liệu gốc.
- **Idempotency.** Dùng khoá `sha256(nội dung) + phiên bản policy + phiên bản judge`.
- **Khi policy đổi,** chạy lại việc quét, xuất danh sách verdict thay đổi, và ghi `guard_decision` / `guard_policy` vào metadata của vector store để lọc lúc truy xuất.

## 3. Thực tế lúc truy vấn

- **Ngân sách độ trễ.** Mỗi filter của Azure thêm 100-300 ms. Stack điển hình năm 2026 gồm cổng nhanh 20-50 ms và classifier 8B khoảng 459 ms ở p95. Mục tiêu hợp lý: **p50 ≤ 150 ms, p95 ≤ 400 ms** cộng thêm cho query và context.
- **Song song hoá.** Kiểm query cùng lúc với truy xuất. Kiểm top-k sau rerank (5-20 chunk) song song.
- **Streaming.** Kiểm theo từng đoạn, có vùng chồng lấp và tín hiệu rút lại, như NeMo; Dify gửi các đoạn 100 ký tự.
- **Cache.** Chunk truy xuất lặp lại rất nhiều giữa các câu hỏi. Kết quả của lúc ingest dùng lại được lúc truy xuất.
- **Groundedness và trích dẫn** là yêu cầu mặc định của khách hàng; Bedrock, Azure và Granite Guardian đã đặt chuẩn này.

## 4. Yêu cầu doanh nghiệp

- **Đa tenant:** tenant → app → profile. Hàng đợi review và audit phải tách theo tenant.
- **ACL:** phân quyền truy xuất thuộc retriever. Guardrail chỉ kiểm tra chéo giữa `acl` của chunk và quyền của người hỏi (OWASP LLM08).
- **Nơi lưu dữ liệu ở Việt Nam:**
  - Luật BVDLCN 91/2025 và Nghị định 356/2025 coi việc xử lý trên cloud nước ngoài là chuyển dữ liệu xuyên biên giới, phải đánh giá tác động và nộp hồ sơ trong 60 ngày; mức phạt có thể tới 5% doanh thu tại Việt Nam.
  - Nghị định hướng dẫn của Luật An ninh mạng 116/2025 về lưu trữ dữ liệu tại Việt Nam **cần kiểm tra lại** khi được ban hành.
  - Hệ quả: **cần triển khai được on-prem hoặc trên cloud trong nước, với judge chạy nội bộ.**
- **Audit và SIEM:** log chuỗi băm, xuất syslog/OTLP/Splunk. Nội dung chỉ lưu dạng hash hoặc bản đã che.
- **Phân quyền review:** reviewer, approver, policy-admin, auditor; đăng nhập SSO.
- **Fail-open/closed theo từng điểm kiểm tra;** luôn ghi trạng thái `degraded`.
- **Quan sát:** OpenTelemetry GenAI semantic conventions và Prometheus.

## 5. Mối đe doạ đặc thù RAG khách hàng hỏi

1. **Injection gián tiếp trong tài liệu**, gồm cả chữ ẩn, ký tự Unicode tag hoặc zero-width, và văn bản OCR từ ảnh.
2. **Đầu độc dữ liệu.** PoisonedRAG đạt khoảng 90% thành công chỉ với 5 đoạn văn cài vào kho hàng triệu tài liệu.
3. **Lộ dữ liệu cá nhân từ kho tài liệu**, đặc biệt các định danh Việt Nam.
4. **Truy xuất vượt quyền** (OWASP LLM08).
5. **Bí mật trong tài liệu:** nên phát hiện bằng regex/entropy, không bằng LLM.
6. **Câu trả lời bịa, không bám nguồn.**

## 6. Hệ sinh thái RAG tại Việt Nam

- **FPT AI Factory:** GPU trong nước, định vị "sovereign AI". Tích hợp qua HTTP.
- **Viettel AI:** hạ tầng DGX; khối chính phủ chỉ chạy on-prem.
- **VNPT SmartBot:** nền tảng đóng. Tích hợp qua webhook hoặc gateway.
- **GreenNode (VNG):** MaaS hơn 20 model, dữ liệu lưu tại Việt Nam, SLA 99,99%. Phù hợp để chạy guardrail dạng container và host judge nội bộ.
- **MISA:** đã chuyển trợ lý AVA về hạ tầng on-prem vì chi phí, bảo mật và độ trễ.
- **Model mở:** Vistral-7B, Arcee-VyLinh, SeaLLM, SEA-LION, GreenMind, chạy qua vLLM hoặc NIM.
- **Xu hướng chung:** on-prem hoặc cloud trong nước, với Dify, RAGFlow, Open WebUI, LangChain, n8n ở phía trên. **Bắt buộc có Docker/Helm, chạy được air-gapped, và có judge nội bộ.**

## 7. Các model judge có thể cắm vào

| Backend | Đầu vào | Đầu ra | Gộp câu hỏi | Ghi chú |
| --- | --- | --- | --- | --- |
| TypeSafe Jev | `POST /v1/systemone {state, questions}` | choice (xác suất từng nhãn), noul, score | nhiều câu hỏi mỗi request | host tại Mỹ, 70-500 ms |
| OpenAI Decisions API | câu hỏi + danh sách đáp án + context | một đáp án (confidence: **chưa rõ**) | chưa rõ | preview; GPT-6 Luna; có ảnh |
| OpenAI Moderation | văn bản / ảnh | 13 nhóm cố định | mảng | miễn phí |
| gpt-oss-safeguard | policy dạng prompt | nhãn + giải thích | qua lớp serving | tự host |
| Llama Guard 4 | taxonomy S1-S14 cố định | safe/unsafe + mã nhóm | qua lớp serving | không có tiếng Việt |
| Granite Guardian | tên rủi ro hoặc tiêu chí tự định nghĩa | yes/no + xác suất | qua lớp serving | có groundedness; tiếng Anh |
| SEA-Guard | văn bản | safe/unsafe | qua lớp serving | **có tiếng Việt** |
| LLM-as-judge | JSON structured output | nhãn + confidence tự báo | N câu mỗi prompt | mọi model |

**Lớp adapter phải chuẩn hoá:**
- hình dạng câu hỏi (choice / yes-no / score);
- xác suất (native, logprob, hay confidence tự báo);
- cách gộp câu hỏi;
- giới hạn context;
- nơi dữ liệu được xử lý (residency);
- phiên bản model, để ghi audit và làm khoá cache.

## Nguồn chính

- **Framework:**
  - https://docs.langchain.com/oss/python/langchain/guardrails
  - https://developers.llamaindex.ai/python/framework/module_guides/loading/ingestion_pipeline/transformations/
  - https://docs.haystack.deepset.ai/docs/llmmessagesrouter
  - https://docs.dify.ai/en/self-host/use-dify/workspace/api-extension/moderation-api-extension
  - https://docs.openwebui.com/features/extensibility/plugin/functions/filter/
  - https://docs.spring.io/spring-ai/reference/api/retrieval-augmented-generation.html
- **RAG được quản lý:**
  - https://docs.aws.amazon.com/bedrock/latest/userguide/kb-custom-transformation.html
  - https://learn.microsoft.com/en-us/azure/search/cognitive-search-custom-skill-web-api
  - https://docs.cloud.google.com/vertex-ai/generative-ai/docs/rag-engine/rag-overview
  - https://developers.openai.com/api/docs/guides/tools-file-search
- **Judge:**
  - https://www.marktechpost.com/2026/09/19/typesafe-ai-releases-jev/
  - https://www.orcarouter.ai/blog/openai-decisions-api-gpt-6-luna
  - https://thenewstack.io/openai-decision-api-luna/
  - https://huggingface.co/meta-llama/Llama-Guard-4-12B
  - https://huggingface.co/ibm-granite/granite-guardian-4.1-8b
  - https://huggingface.co/aisingapore/Qwen-SEA-Guard-8B-2602
- **Mối đe doạ và quan sát:**
  - https://arxiv.org/abs/2402.07867 (PoisonedRAG)
  - https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/
- **Pháp luật Việt Nam:**
  - https://thuvienphapluat.vn/van-ban/EN/Cong-nghe-thong-tin/Law-116-2025-QH15-Cybersecurity/688491/tieng-anh.aspx
  - https://www.vietnam-briefing.com/news/vietnam-personal-data-protection-regulation-decree-356.html/
  - https://english.luatvietnam.vn/law-no-134-2025-qh15-dated-december-10-2025-of-the-national-assembly-on-artificial-intelligence-422299-doc1.html
- **Hệ sinh thái Việt Nam:**
  - https://greennode.ai/
  - https://www.nvidia.com/en-us/case-studies/misa-ai-factory-enterprise-workflow-automation-vietnam/
  - https://www.arcee.ai/blog/introducing-arcee-vylinh-a-powerful-3b-parameter-vietnamese-language-model
