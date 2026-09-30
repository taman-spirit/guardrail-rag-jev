# Nghiên cứu thị trường: guardrail cho hệ thống RAG

*Cập nhật 30/09/2026.* Tổng hợp từ tài liệu chính thức của các vendor. Một số thông tin chỉ có ở
nguồn thứ cấp; những chỗ đó được ghi **(thứ cấp)**. Tài liệu này dùng để định hướng sản phẩm, không
phải đánh giá kỹ thuật độc lập.

## Tóm tắt

1. **Chưa vendor nào có gói tuân thủ pháp luật Việt Nam.** Danh sách vendor bảo mật LLM cho thị trường Việt Nam năm 2026 không có sản phẩm nào phủ Luật BVDLCN, Luật An ninh mạng hay Luật Trí tuệ nhân tạo [49]. Đây là khoảng trống lớn nhất.
2. **Căn cứ pháp lý đã thay đổi trong 2025-2026:**
   - Luật Bảo vệ dữ liệu cá nhân (số 91/2025/QH15) có hiệu lực từ 01/01/2026. Nghị định 356/2025/NĐ-CP thay thế Nghị định 13/2023/NĐ-CP [50].
   - Luật An ninh mạng 2025 (số 116/2025/QH15) có hiệu lực từ 01/07/2026, thay thế Luật An ninh mạng 2018 và Luật An toàn thông tin mạng 2015 [51].
   - Luật Trí tuệ nhân tạo (số 134/2025/QH15) có hiệu lực từ 01/03/2026, yêu cầu gắn nhãn nội dung do AI tạo; thời gian chuyển tiếp đến 01/03/2027, hoặc 01/09/2027 với y tế, giáo dục, tài chính [52].
3. **Gần như không có công cụ kiểm tra bám nguồn (groundedness) hỗ trợ tiếng Việt:** Bedrock chỉ hỗ trợ EN/FR/ES, Azure chỉ tiếng Anh, Granite Guardian chỉ tiếng Anh, Vectara HHEM có 8 ngôn ngữ nhưng không có tiếng Việt [2][6][39][41].
4. **Thị trường biến động mạnh:**
   - Protect AI về Palo Alto [24]; LLM Guard được lưu trữ (archived) 07/2026 [22]; Rebuff cũng đã archived [23].
   - Lakera về Check Point [19].
   - Pangea về CrowdStrike [34][35].
   - Galileo Protect ngừng từ 06/2026 [37].
   - Guardrails AI về Harvey [17].
5. **Chỉ Pangea có bộ kiểm tra riêng cho bước ingest RAG và audit log chống sửa** [34]. Không vendor nào có hàng đợi review tích hợp sẵn.

## Bảng so sánh

I = ingest, Q = query, C = context truy xuất, A = answer. Y = có, P = một phần, N = không, ? = chưa công bố.

| Sản phẩm | I | Q | C | A | PII | Injection trực tiếp / gián tiếp | Groundedness | Hành động | Audit | Policy tuỳ biến | Tiếng Việt | Triển khai |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| AWS Bedrock Guardrails | P | Y | P | Y | Y | Y / P | Y | chặn, che | P | Y | Y (trừ grounding) | SaaS |
| Azure AI Content Safety | P | Y | Y | Y | P | Y / Y | Y (EN) | ghi chú, chặn, sửa | P | P | P (chỉ PII) | SaaS |
| Google Model Armor | P | Y | Y | Y | Y | Y / P | N | kiểm tra, chặn | Y | P | N | SaaS |
| NVIDIA NeMo Guardrails | N | Y | Y | Y | Y | Y / P | Y | chặn, luồng riêng | P | Y (Colang) | tuỳ model | OSS |
| Lakera Guard | P | Y | Y | Y | Y | Y / Y | N | gắn cờ | ? | P | **Y** | SaaS |
| Llama Guard 4 / Prompt Guard 2 | N | Y | P | Y | P | Y / P | N | chỉ phân loại | N | P | N | OSS |
| Pangea / Falcon AIDR | **Y** | Y | P | Y | Y | Y / P | N | chặn, che, mã hoá, defang | **Y (chống sửa)** | Y | ? | SaaS, edge |
| Granite Guardian | N | Y | Y | Y | N | Y / N | Y | chỉ phân loại | N | Y | N | OSS |
| Presidio | Y | Y | Y | Y | Y | N | N | che, băm | N | Y | N | OSS |
| gpt-oss-safeguard | N | Y | P | Y | P | P | N | chỉ phân loại | N | **Y** | P | OSS |
| SEA-Guard (AI Singapore) | N | Y | N | Y | N | P | N | safe/unsafe | N | N | **Y** | OSS |
| **guardrail-rag-jev** | **Y** | **Y** | **Y** | **Y** | **Y (định danh VN)** | **Y / Y** | **Y** | **pass, che, review, loại, defang** | **Y (chuỗi băm)** | **Y (gói luật, bật/tắt, khoá)** | **Y** | **tự host, judge nội bộ** |

## Ghi chú từng sản phẩm

- **AWS Bedrock Guardrails.**
  - Kiểm tra natively ở query và answer. `ApplyGuardrail` kiểm tra được văn bản bất kỳ.
  - Có contextual grounding với ngưỡng 0-0,99, và Automated Reasoning (chỉ phát hiện).
  - Nội dung bị chặn xuất hiện nguyên văn trong invocation log [1][3][4].
  - Giá theo 1.000 text unit (mỗi unit 1.000 ký tự), ví dụ content filter $0,15 [5].
- **Azure AI Content Safety.**
  - Prompt Shields kiểm tra prompt kèm tối đa 5 tài liệu (tổng 10k ký tự) để phát hiện "document attacks", tức injection gián tiếp [7].
  - Có groundedness kèm tự sửa (preview) và kiểm tra nội dung có bản quyền [8].
- **Google Model Armor.**
  - Quét được file PDF/Office tới 4 MB, nên dùng được ở bước ingest.
  - Có "floor settings" làm mức tối thiểu cho mọi template; có chế độ chỉ kiểm tra [11].
- **NVIDIA NeMo Guardrails.**
  - Có 5 loại rail, trong đó có *retrieval rail* để lọc chunk.
  - Chất lượng tiếng Việt phụ thuộc model cắm vào [13][15].
- **Lakera (Check Point).**
  - Phát hiện injection gián tiếp khi nội dung được gửi với role `tool`.
  - Độ nhạy L1-L4, có danh sách allow/deny, hỗ trợ tiếng Việt [19][20].
- **Pangea → CrowdStrike Falcon AIDR.** Đối thủ gần nhất về cấu trúc:
  - có bộ "recipe" riêng cho RAG ingestion;
  - hành động gồm chặn, che, **mã hoá**, **defang**;
  - audit log chống sửa [34].
- **OpenAI.**
  - `omni-moderation` miễn phí, 13 nhóm [42].
  - `gpt-oss-safeguard` nhận policy viết bằng lời ngay lúc suy luận, tương tự Jev [43].
  - Decisions API trên GPT-6 Luna mới ở dạng preview (xem [providers.vi.md](providers.vi.md)).
- **Đông Nam Á.**
  - SEA-Guard hỗ trợ tiếng Việt, chỉ trả safe/unsafe [45].
  - LionGuard 2 không hỗ trợ tiếng Việt [46].
  - FPT, Viettel, VNPT, CMC chưa có sản phẩm guardrail LLM công khai [47][48].

## Khoảng trống sản phẩm có thể lấp

| Khoảng trống | guardrail-rag-jev đáp ứng bằng |
| --- | --- |
| Tuân thủ pháp luật Việt Nam, bật/tắt theo từng luật | 3 gói `vn-cybersecurity`, `vn-ai`, `vn-personal-data`; mỗi vi phạm kèm căn cứ |
| Định danh cá nhân Việt Nam (CCCD, SĐT, số tài khoản, BHXH) | detector tất định, che theo vị trí chính xác |
| Ingest là một điểm kiểm tra chính thức | `ingest` + gom kết quả theo tài liệu + cách ly cả tài liệu khi bị cài chỉ thị |
| Hàng đợi người duyệt | review queue; quyết định thành override theo hash; webhook có chữ ký |
| Audit chống sửa, không lộ dữ liệu cá nhân | chuỗi băm, `verify()`; mặc định chỉ lưu nội dung đã che |
| Ổn định, không phụ thuộc một vendor | provider thay thế được; judge nội bộ; kiểm soát residency |

## Tính năng đã áp dụng từ đối thủ

| Tính năng | Lấy ý tưởng từ | Trạng thái |
| --- | --- | --- |
| Profile riêng cho từng điểm kiểm tra | Pangea recipes, Azure scan points | có (`enforcement.<surface>`) |
| Injection gián tiếp trong từng chunk | Azure Prompt Shields, Lakera | có (`ipi`, detector ký tự ẩn) |
| Groundedness và relevance | Granite Guardian, Bedrock | có (`groundedness`, `relevance`, `answer_relevance`) |
| Chế độ shadow (chỉ ghi nhận) | Azure annotate, Model Armor inspect-only | có (`mode: shadow`) |
| Defang URL | Pangea | có |
| Mức tối thiểu không thể nới | Model Armor floor settings | có (`policy.locked`) |
| Mức nhạy cảm và danh sách allow/deny | Lakera L1-L4, Bedrock word filters | có (`sensitivity`, `patterns`) |
| Không ghi nội dung thô vào log | bài học từ Bedrock | có (`store_content: redacted`) |
| Gắn nhãn nội dung AI | Luật Trí tuệ nhân tạo | có (`ai_label`) |
| Webhook sang SIEM | Galileo, Cisco | có (`audit.webhook_url`) |
| Ẩn danh hoá có thể đảo ngược (vault) | LLM Guard | chưa |
| Tự sửa câu trả lời bịa | Azure | chưa |
| Suy luận kèm trích dẫn điều luật | gpt-oss-safeguard | chưa; có thể dùng `llm-judge` |

## Nguồn

1. https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-components.html
2. https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-supported-languages.html
3. https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-contextual-grounding-check.html
4. https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html
5. https://aws.amazon.com/bedrock/pricing/
6. https://learn.microsoft.com/en-us/azure/ai-services/content-safety/overview
7. https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection
8. https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/groundedness
11. https://docs.cloud.google.com/model-armor/overview
13. https://docs.nvidia.com/nemo/guardrails/latest/about/rail-types.html
15. https://huggingface.co/nvidia/Llama-3.1-Nemotron-Safety-Guard-8B-v3
17. https://www.harvey.ai/blog/guardrails-ai-joins-harvey
19. https://docs.lakera.ai/docs/prompt-defense
20. https://docs.lakera.ai/docs/defenses
22. https://github.com/protectai/llm-guard
23. https://github.com/protectai/rebuff
24. https://www.paloaltonetworks.com/company/press/2025/palo-alto-networks-completes-acquisition-of-protect-ai
34. https://pangea.cloud/docs/ai-guard/overview · https://pangea.cloud/docs/ai-guard/recipes
35. https://www.crowdstrike.com/en-us/press-releases/crowdstrike-announces-general-availability-of-falcon-ai-detection-and-response/
37. https://docs.galileo.ai/concepts/protect/overview
39. https://www.vectara.com/blog/hhem-expanded-language-support
41. https://www.ibm.com/granite/docs/models/guardian
42. https://developers.openai.com/api/docs/guides/moderation
43. https://openai.com/index/introducing-gpt-oss-safeguard/
45. https://huggingface.co/aisingapore/Qwen-SEA-Guard-8B-2602
46. https://huggingface.co/govtech/lionguard-2
47. https://fpt-is.com/en/fpt-introduces-a-comprehensive-security-model-based-on-the-5-level-ai-maturity-framework-at-vietnam-security-summit-2026/
48. https://baoquangninh.vn/khi-ai-biet-kiem-chung-su-that-buoc-tien-moi-tu-viettel-ai-tai-naacl-2025-3358734.html
49. https://guardion.ai/ai-security-index/best/llm-security-for-lawtechs-in-vietnam (do vendor công bố)
50. https://english.luatvietnam.vn/legal-updates/the-latest-law-on-personal-data-protection-and-the-guiding-documents-892-106778-article.html
51. https://www.rajahtannasia.com/viewpoints/law-on-cybersecurity-comes-into-operation-on-1-july-2026-establishing-a-unified-legal-framework-on-cybersecurity-and-network-information-security-in-vietnam/
52. https://www.bakermckenzie.com/en/insight/publications/2026/02/vietnam-artificial-intelligence-law-foundation-and-outlook
