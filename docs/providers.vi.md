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
| `granite-guardian` | IBM Granite Guardian | không (từng tiêu chí) | logprob Yes/No | `local` nếu URL nội bộ | tiêu chí tuỳ biến, groundedness |
| `sea-guard` | AI Singapore SEA-Guard | không (từng tiêu chí) | logprob Yes/No | `local` nếu URL nội bộ | classifier có tiếng Việt |
| `classifier` | classifier có/không bất kỳ | không | logprob Yes/No | `local` nếu URL nội bộ | model an toàn khác |
| `llama-guard` | Meta Llama Guard | có (một lần phân loại) | logprob unsafe | `local` nếu URL nội bộ | chỉ các nhóm S1-S14; dùng trong `routed` |
| `routed` | nhiều provider | - | - | theo từng thành viên | chia câu hỏi theo tên |
| `plugin` | class của bạn | tuỳ | tuỳ | khai báo | model chưa có adapter |
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

### Classifier an toàn tự host (SEA-Guard, Granite Guardian, Llama Guard)

Các classifier chạy sau vLLM hoặc một server có API tương thích OpenAI. SEA-Guard và Granite Guardian
trả lời có/không cho từng tiêu chí, và xác suất lấy từ logprob. `Normalizing` tự tách câu hỏi
chọn-một thành từng câu có/không cho mỗi nhãn:

```yaml
providers:
  sea_guard: {type: sea-guard, base_url: http://sea-guard:8000/v1, model: aisingapore/Qwen-SEA-Guard-8B-2602, residency: local}
  granite:   {type: granite-guardian, base_url: http://granite:8000/v1, model: ibm-granite/granite-guardian-4.1-8b, residency: local}
```

Mỗi nhóm là một request, nên một lần kiểm tra ingest cần vài chục request song song. Classifier nhỏ
(8B) chạy trên GPU chịu được mức này, nhưng hãy đo độ trễ trước khi dùng cho `query`.

Llama Guard chỉ biết taxonomy S1-S14. Hãy dùng nó trong `routed`, để các nhóm nó không biết (gói luật
Việt Nam, injection, tín hiệu) được hỏi một judge khác:

```yaml
providers:
  llama_guard: {type: llama-guard, base_url: http://llama-guard:8000/v1, model: meta-llama/Llama-Guard-4-12B, residency: local}
  local: {type: llm-judge, base_url: http://vllm:8000/v1, model: Viet-Mistral/Vistral-7B-Chat, residency: local}
  mixed:
    type: routed
    routes: [{match: ["s_*", "m_*", "l_*"], provider: llama_guard}]
    default: local
provider: mixed
```

Định dạng prompt theo model card đã công bố tại thời điểm viết. Hãy kiểm lại với phiên bản model bạn
chạy, và hiệu chỉnh ngưỡng (xem bên dưới).

### Plugin

Với model chưa có adapter, hãy viết một class có `name`, `capabilities` và `decide()`. Khai báo đúng
những gì model làm được natively; `Normalizing` lo phần còn lại:

```python
from guardrail_rag_jev.providers import Answers, Capabilities, Response

class MyGuard:
    name = "my-guard"
    capabilities = Capabilities(batch=False, choice=False, yes_no=True, score=False)

    def decide(self, state, questions, *, timeout=None) -> Response:
        (name, q), = questions.items()          # một câu có/không
        p = ...                                  # gọi model: xác suất q["instructions"] đúng với state
        return Response(Answers({name: {"type": "noul", "noul": p}}), "my-guard", provider=self.name)
```

```yaml
providers:
  mine: {type: plugin, class: my_company.guards:MyGuard, residency: local}
```

## Quy trình chuyển model an toàn (ví dụ Jev → Luna)

1. **Chạy shadow.** Jev vẫn quyết định. Luna trả lời cùng bộ câu hỏi ở chế độ nền, trên một phần traffic:
   ```yaml
   shadow: {provider: luna, sample: 0.2}
   ```
   Mỗi lần hai model khác nhau về mức xử lý hoặc về nhóm vi phạm, audit ghi một bản ghi `shadow.compare`, và metric `guardrail_shadow_disagreements_total` tăng.
2. **Đo trên bộ dữ liệu có nhãn.** Chạy cả hai model trên cùng bộ trường hợp, và ghi lại câu trả lời thô:
   ```bash
   guardrail-rag-jev -c jev.yaml  eval --dataset datasets/vi-rag-v1.jsonl --record runs/jev.jsonl
   guardrail-rag-jev -c luna.yaml eval --dataset datasets/vi-rag-v1.jsonl --record runs/luna.jsonl
   ```
   Lệnh in ra độ chính xác quyết định, tỷ lệ chặn nhầm, tỷ lệ bắt được và precision/recall theo nhóm. Bổ sung vào bộ dữ liệu các bản ghi `shadow.compare` (`GET /v1/audit?type=shadow.compare`) sau khi người duyệt gán nhãn đúng sai.
3. **Hiệu chỉnh.** Phát lại bản ghi của Luna, không gọi mạng, và dò hệ số ngưỡng cho từng nhóm:
   ```bash
   guardrail-rag-jev -c luna.yaml calibrate --dataset datasets/vi-rag-v1.jsonl \
       --replay runs/luna.jsonl --out calibration/luna.json --name calibration-luna --max-false-hold 0.05
   ```
   Kết quả là một policy patch có ngưỡng riêng cho Luna, nạp qua `providers.luna.calibration`. Lặp lại bước 1-3 cho đến khi tỷ lệ bất đồng chấp nhận được.
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
