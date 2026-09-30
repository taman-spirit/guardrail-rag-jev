# Tuân thủ pháp luật Việt Nam cho hệ thống RAG

> Đây là hướng dẫn kỹ thuật, không phải tư vấn pháp lý. Hãy đối chiếu với văn bản luật và văn bản
> hướng dẫn đang có hiệu lực, và để bộ phận pháp chế duyệt policy trước khi vận hành. Ngưỡng trong các
> gói là con số được chọn, chưa phải con số đo được trên dữ liệu của bạn.

Ba gói luật được ghép lên policy chuẩn `standard-rag-v1`. Mỗi gói bật hoặc tắt độc lập:

| Gói | Căn cứ | Hiệu lực |
| --- | --- | --- |
| `vn-cybersecurity` | Luật An ninh mạng 2025 (Luật số 116/2025/QH15), thay thế Luật An ninh mạng 2018 và Luật An toàn thông tin mạng 2015 | 01/07/2026 |
| `vn-ai` | Luật Trí tuệ nhân tạo (Luật số 134/2025/QH15) | 01/03/2026; chuyển tiếp đến 2027 cho một số lĩnh vực |
| `vn-personal-data` | Luật Bảo vệ dữ liệu cá nhân (Luật số 91/2025/QH15), Nghị định 356/2025/NĐ-CP (thay Nghị định 13/2023/NĐ-CP) | 01/01/2026 |

Mỗi vi phạm guardrail trả về đều kèm `refs` (căn cứ), `pack` (gói), tên nhóm bằng tiếng Việt và tiếng
Anh, và vị trí trong văn bản khi xác định được.

## Gói `vn-cybersecurity`

| Nhóm | Guardrail xử lý | Guardrail **không** xử lý |
| --- | --- | --- |
| `vsv` Chủ quyền lãnh thổ | Phủ nhận, xuyên tạc chủ quyền; trình bày yêu sách của nước khác (Xisha, Nansha, "đường chín đoạn") như sự thật; bản đồ bỏ sót lãnh thổ | Thời tiết, du lịch, tin tức, lịch sử, câu hỏi về địa vị pháp lý |
| `vas` Chống phá Nhà nước | Tuyên truyền chống Nhà nước, kích động lật đổ, chia rẽ, xuyên tạc lịch sử | Câu hỏi về thể chế, pháp luật, chính sách; góp ý hợp pháp; tin tức |
| `vld` Lãnh tụ, lãnh đạo, biểu tượng quốc gia | Xúc phạm, bịa đặt về lãnh tụ, lãnh đạo, anh hùng dân tộc, Quốc kỳ, Quốc huy, Quốc ca | Tiểu sử, chức danh, trích dẫn, tin tức |
| `vcs` Thông tin sai sự thật, gây rối | Tin giả gây hoang mang, kích động gây rối, hướng dẫn tấn công hệ thống thông tin | Hỏi kiểm chứng tin đồn, bài đính chính, kiến thức phòng thủ |

- **Nhắc đến một cách trung tính không phải vi phạm.** Rule `neutral-mention-is-not-a-violation` giới hạn kết quả ở mức ghi nhận (`flag`) và bỏ qua cổng confidence thấp.
- **Câu hỏi về chủ quyền được trả lời kèm đoạn khẳng định viết sẵn.** Ví dụ câu hỏi "Trường Sa thuộc nước nào?": câu trả lời được dùng, và kết thúc bằng đoạn khẳng định chủ quyền giữ nguyên từng ký tự như trong gói (`notices`). Model không tự viết đoạn này.
- **Với tài liệu ingest,** rule `reference-material-softens` hạ một bậc cho tài liệu tham khảo (luật, tin tức, bài học thuật), nhưng **không** áp dụng cho `vsv` và `vld`. Một bài "bách khoa" ghi Hoàng Sa thuộc nước khác vẫn bị giữ lại.

## Gói `vn-ai`

| Nhóm | Guardrail xử lý | Guardrail **không** xử lý |
| --- | --- | --- |
| `vai` Dùng AI để giả mạo, lừa dối | Deepfake, giả giọng, mạo danh người hoặc tổ chức thật; trình bày nội dung AI như do người viết hoặc như văn bản chính thức để lừa dối; AI tự nhận là người khi được hỏi thật lòng | Giải thích AI hoạt động thế nào; nội dung hư cấu có ghi rõ; hỗ trợ viết thông thường |
| `vam` Dùng AI thao túng, lợi dụng người yếu thế | Thao túng nhận thức hoặc quyết định trái lợi ích người dùng; lợi dụng trẻ em, người cao tuổi, người yếu thế; chấm điểm, lập hồ sơ ngầm để đối xử bất công | Marketing thông thường; cá nhân hoá có đồng ý; nghiên cứu, báo chí |

- **Nhãn minh bạch.** Khi `enforcement.answer.ai_label: true` (mặc định), câu trả lời được dùng sẽ kèm dòng "Nội dung này do hệ thống trí tuệ nhân tạo tạo ra." bằng ngôn ngữ của người dùng.
- **AI không được tự nhận là người.** Tín hiệu `claims_human` ≥ 0,7 trên câu trả lời sẽ giữ câu trả lời lại chờ người duyệt, không chặn hẳn, để người duyệt phân biệt được nhân vật nhập vai với lừa dối thật.

## Gói `vn-personal-data`

| Nhóm | Guardrail xử lý | Cách xử lý |
| --- | --- | --- |
| `prv` Dữ liệu cá nhân cơ bản | Dữ liệu của **cá nhân**: số CCCD, SĐT riêng, địa chỉ nhà, email cá nhân, số tài khoản; yêu cầu tìm, lập hồ sơ, theo dõi một người | Che (`redact`) các vị trí detector tìm được |
| `vsd` Dữ liệu cá nhân nhạy cảm | Sức khoẻ, di truyền, sinh trắc, đời sống tình dục, quan điểm chính trị hoặc tôn giáo, dân tộc, tiền án, tài chính, vị trí, dữ liệu trẻ em, gắn với một người xác định | Ngưỡng chặt hơn; che nếu có vị trí, không có thì giữ lại chờ duyệt |

- **Detector tất định cho định danh Việt Nam:** `vn_cccd` (12 số, kiểm tra mã tỉnh), `vn_phone`, `vn_bank_account` (sau từ khoá STK / số tài khoản), `vn_passport`, `vn_social_insurance` (BHXH), `vn_license_plate`. Kèm theo đó là các detector chung: email, thẻ thanh toán (kiểm tra Luhn), khoá bí mật, ký tự ẩn.
- **Thông tin liên hệ của tổ chức không phải dữ liệu cá nhân.** Khi model xác định chủ thể là tổ chức (`data_subject: organization`), hotline, email hỗ trợ và số tổng đài được giữ nguyên. Số định danh (CCCD, hộ chiếu, tài khoản) thì luôn bị che.
- **Ingest che trước khi index** (`redact_always: true`). Đây là nguyên tắc tối thiểu hoá dữ liệu: kho vector không chứa định danh ngay từ đầu.
- **Audit log không lưu dữ liệu cá nhân dạng thô** (`audit.store_content: redacted`). Hàng đợi review có thể lưu bản đầy đủ để người duyệt làm việc, kèm thời hạn xoá (`review.retention_days`).

## Nơi xử lý dữ liệu

Gửi nội dung có dữ liệu cá nhân tới một judge đặt ở nước ngoài có thể là chuyển dữ liệu xuyên biên
giới theo Luật BVDLCN và Nghị định 356/2025/NĐ-CP. Để giữ mọi lần kiểm tra ở trong nước:

```yaml
provider: local
providers:
  local: {type: llm-judge, base_url: http://vllm:8000/v1, model: Viet-Mistral/Vistral-7B-Chat, api_key: "", residency: local}
residency: {allow: [local, vn_hosted]}
```

Xem [providers.vi.md](providers.vi.md).

## Bật, tắt, khoá

```yaml
policy:
  packs: {vn-cybersecurity: true, vn-ai: true, vn-personal-data: true}
  categories:
    vam: {enabled: false}            # tắt một nhóm
    vsd: {sensitivity: strict}       # chặt hơn: mọi ngưỡng × 0,7
  locked: [vn-cybersecurity, vn-personal-data, cse]   # API runtime không tắt được
```

Thay đổi lúc chạy (cần quyền admin):

```bash
curl -X PATCH $URL/v1/policy -H "Authorization: Bearer $ADMIN_KEY" \
     -d '{"packs": {"vn-ai": false}, "categories": {"spc": {"enabled": false}}}'
```

- **Khi thay đổi,** guardrail dựng policy mới và kiểm tra hợp lệ trước khi thay thế policy đang chạy, lưu vào `state_path` để giữ qua lần khởi động lại, và ghi audit `policy.changed` gồm người thay đổi cùng fingerprint trước và sau.
- **Tắt một gói sẽ gỡ toàn bộ những gì gói đó thêm vào:** nhóm vi phạm, rule, câu trả lời viết sẵn và detector.

## Các bước đưa vào vận hành

1. **Phạm vi.** Liệt kê nguồn tài liệu (ingest), kênh hỏi đáp (query/answer), và người chịu trách nhiệm policy.
2. **Chạy thử.** Bật mọi gói với `enforcement: {mode: shadow}` trong 1-2 tuần. Guardrail ghi lại "lẽ ra đã làm gì" nhưng không chặn.
3. **Đo.** Xem audit và hàng đợi review, gán nhãn các trường hợp chặn nhầm và bỏ sót, rồi hiệu chỉnh ngưỡng bằng `categories.<id>.thresholds` hoặc `sensitivity`.
4. **Bật thật** theo từng điểm kiểm tra: ingest trước, answer sau.
5. **Duy trì.** Người duyệt xử lý hàng đợi hằng ngày. Kiểm tra `GET /v1/audit/verify` định kỳ, và lưu `GET /v1/audit/head` ra ngoài hệ thống.
