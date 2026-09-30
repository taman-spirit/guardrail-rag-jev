# Chọn model quyết định: Jev, OpenAI Luna hay model khác

Guardrail không gắn chặt với một model nào. Policy (các nhóm vi phạm, gói luật, ngưỡng) và engine
quyết định giữ nguyên khi đổi model. Chỉ có **provider**, tức lớp hỏi model, là thay đổi.

## Giao thức chung

Mỗi lần kiểm tra, guardrail gửi một **state** (nội dung cần xét) và một **bộ câu hỏi**. Có ba loại
câu hỏi:

| Loại | Hỏi gì | Câu trả lời chuẩn |
| --- | --- | --- |
| `choice` | chọn một nhãn trong danh sách (vd. nhóm vi phạm nặng nhất) | `{"choice", "confidence", "probabilities": {nhãn: xác suất}}` |
| `noul` | xác suất một mệnh đề đúng (vd. "đoạn này chứa chỉ thị gửi tới AI") | `{"noul": 0..1}` |
| `score` | mức trên một thang (vd. độ bám nguồn 0-3) | `{"score", "confidence"}` |

Jev dùng đúng giao thức này. Với model khác, lớp `Normalizing` tự bù những gì model không làm được:

| Model không có | Normalizing làm |
| --- | --- |
| gộp nhiều câu hỏi trong một request | tách ra, gọi song song |
| câu hỏi có/không | hỏi thành `choice` với hai nhãn `yes` / `no` |
| câu hỏi thang điểm | hỏi thành `choice` trên các mức, đọc lại bằng giá trị kỳ vọng |
| xác suất từng nhãn | nhãn được chọn nhận confidence, các nhãn khác chia đều phần còn lại |

## Các provider có sẵn

| `type` | Model | Gộp câu hỏi | Xác suất | Nơi xử lý mặc định | Khi nào dùng |
| --- | --- | --- | --- | --- | --- |
| `jev` | TypeSafe Jev | có | đã hiệu chỉnh | `offshore` | mặc định: nhanh (70-500 ms), rẻ, không tốn token đầu ra |
| `openai-decisions` | OpenAI Decisions API (GPT-6 Luna) | không (tách song song) | một confidence | `offshore` | **thử nghiệm**: khi cần nhận ảnh; chạy shadow trước |
| `llm-judge` | mọi model có API tương thích OpenAI | có (chia nhóm) | tự báo, chưa hiệu chỉnh | `local` nếu URL nội bộ | dữ liệu phải ở trong nước hoặc on-prem; làm fallback |
| `fallback` | chuỗi provider | - | - | theo từng thành viên | Jev chính, judge nội bộ dự phòng |
| `plugin` | class của bạn | tuỳ | tuỳ | khai báo | Llama Guard, Granite Guardian, SEA-Guard... |
| `offline` | heuristic từ khoá | - | - | `local` | demo, test. **Không dùng cho nội dung thật** |

### Jev (mặc định)

```yaml
provider: jev
providers:
  jev: {type: jev, api_key: ${JEV_API_KEY}, model: jev-latest, timeout: 5}
```

### OpenAI Decisions API (Luna)

Tại thời điểm viết (30/09/2026), OpenAI mới công bố Decisions API ở dạng preview giới hạn. Mô tả
công khai: đầu vào gồm một câu hỏi, danh sách đáp án và context (văn bản hoặc ảnh); đầu ra là một
đáp án kèm confidence, trong vài trăm mili giây. **Schema request, định dạng confidence và giá
chưa được công bố.** Vì vậy adapter được viết theo mô tả đó, và mọi tên trường đều cấu hình được.
Khi OpenAI công bố schema chính thức, chỉ cần đổi config, không cần sửa code:

```yaml
providers:
  luna:
    type: openai-decisions
    api_key: ${OPENAI_API_KEY}
    model: gpt-6-luna
    path: /decisions                       # đổi khi có endpoint chính thức
    fields:                                # đổi khi có schema chính thức
      question: question
      answers: answers
      context: context
      out_answer: answer
      out_confidence: confidence
      out_probabilities: probabilities
    calibration: ../calibration/luna.json  # ngưỡng hiệu chỉnh riêng cho Luna
```

**Hệ quả với bộ câu hỏi của guardrail:**
- Luna nhận mỗi request một câu hỏi, nên một lần kiểm tra ingest (khoảng 30 câu hỏi) thành khoảng 30 request song song. Độ trễ vẫn ở mức một vòng gọi, nhưng chi phí tăng theo số câu hỏi.
- Không có xác suất cho từng nhãn, nên các rule dựa vào phân phối (sentinel corroboration, confidence gate) kém chính xác hơn. **Bắt buộc hiệu chỉnh lại ngưỡng** trước khi dùng Luna để ra quyết định.

### Judge nội bộ (on-prem hoặc cloud trong nước)

```yaml
providers:
  local:
    type: llm-judge
    base_url: http://vllm:8000/v1           # vLLM, Ollama, NIM, GreenNode MaaS...
    model: Viet-Mistral/Vistral-7B-Chat
    api_key: ""
    max_questions: 24                       # chia bộ câu hỏi thành các nhóm nhỏ hơn
    residency: local
    calibration: ../calibration/vistral.json
residency:
  allow: [local, vn_hosted]                 # từ chối mọi provider offshore
```

`docker compose --profile local up` chạy thêm một vLLM cạnh service.

### Plugin (Llama Guard, Granite Guardian, SEA-Guard...)

```python
from guardrail_rag_jev.providers import Capabilities, Response, Answers

class SeaGuardProvider:
    name = "sea-guard"
    # SEA-Guard chỉ trả safe/unsafe: khai báo đúng, Normalizing lo phần còn lại
    capabilities = Capabilities(batch=False, label_probabilities=False, yes_no=False, score=False)

    def __init__(self, url: str): ...
    def decide(self, state, questions, *, timeout=None) -> Response:
        (name, q), = questions.items()
        label = ...  # gọi model, ánh xạ về một nhãn trong q["criteria"]
        return Response(Answers({name: {"type": "choice", "choice": label, "confidence": 0.9}}), "sea-guard", provider=self.name)
```

```yaml
providers:
  sea_guard: {type: plugin, class: my_company.guards:SeaGuardProvider, options: {url: http://sea-guard:8000}, residency: local}
```

## Quy trình chuyển model an toàn (ví dụ Jev → Luna)

1. **Chạy shadow.** Jev vẫn quyết định. Luna trả lời cùng bộ câu hỏi ở chế độ nền, trên một phần traffic:
   ```yaml
   shadow: {provider: luna, sample: 0.2}
   ```
   Mỗi lần hai model khác nhau về mức xử lý hoặc về nhóm vi phạm, audit ghi một bản ghi `shadow.compare`, và metric `guardrail_shadow_disagreements_total` tăng.
2. **Đo.** Lấy các bản ghi `shadow.compare` qua `GET /v1/audit?type=shadow.compare`, cho người gán nhãn đúng sai, rồi tính tỷ lệ chặn nhầm và bỏ sót của từng model theo từng nhóm.
3. **Hiệu chỉnh.** Viết `calibration/luna.json`. Đây là một policy patch, có thể thay ngưỡng của từng nhóm theo từng điểm kiểm tra:
   ```json
   {"id": "calibration-luna", "categories": {"ipi": {"thresholds": {"default": {"flag": 0.3, "review": 0.5, "block": 0.75}}}}}
   ```
   Lặp lại bước 1-3 cho đến khi tỷ lệ bất đồng chấp nhận được.
4. **Chuyển từng phần.** Dùng `routing` để chuyển từng điểm kiểm tra sang Luna, ví dụ `routing: {ingest: luna}` trước, vì ingest không có người dùng chờ, sai thì chỉ vào hàng đợi review.
5. **Chuyển hẳn.** Đổi `provider: luna`, và giữ Jev làm `fallback` hoặc `shadow` thêm một thời gian.

Mọi bản ghi audit đều ghi `provider`, `model` và `policy` (kèm fingerprint). Nhờ đó luôn biết model
nào, với ngưỡng nào, đã ra một quyết định cụ thể.

## Nơi xử lý dữ liệu (residency)

Mỗi provider thuộc một trong ba lớp: `offshore` (xử lý ở nước ngoài), `vn_hosted` (cloud tại Việt Nam)
hoặc `local` (máy của bạn). Nếu không khai báo:
- `llm-judge` trỏ tới địa chỉ nội bộ (localhost, IP private, `.local`, `.svc`) được coi là `local`;
- mọi provider khác được coi là `offshore`.

Guard **không khởi động** nếu một provider nằm ngoài `residency.allow`, kể cả khi provider đó chỉ nằm
trong chuỗi fallback hay dùng cho shadow.

Theo Luật BVDLCN (91/2025/QH15) và Nghị định 356/2025/NĐ-CP, gửi nội dung có dữ liệu cá nhân tới
một judge ở nước ngoài có thể là chuyển dữ liệu xuyên biên giới, kèm nghĩa vụ đánh giá tác động.
Hãy để bộ phận pháp chế quyết định giá trị của `residency.allow`.
