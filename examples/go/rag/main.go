// A RAG application in Go, guarded at all four checkpoints through the guardrail service.
//
//	# terminal 1: the service (offline heuristic, no API key needed; use a real config in production)
//	guardrail-rag-jev serve --offline --port 8080
//
//	# terminal 2
//	cd examples/go && go run ./rag
//
// Environment: GUARDRAIL_URL (default http://127.0.0.1:8080), GUARDRAIL_CLIENT_KEY,
// GUARDRAIL_REVIEWER_KEY (both empty when the service runs without keys).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/taman-spirit/guardrail-rag-jev/clients/go/guardrailrag"
)

// store is a stand-in for a vector store: chunks with their guard metadata, searched by word overlap.
type store struct {
	chunks []guardrailrag.Chunk
}

func (s *store) add(c guardrailrag.Chunk) { s.chunks = append(s.chunks, c) }

func (s *store) search(query string, k int) []guardrailrag.Chunk {
	words := strings.Fields(strings.ToLower(query))
	type scored struct {
		c     guardrailrag.Chunk
		score int
	}
	var hits []scored
	for _, c := range s.chunks {
		text := strings.ToLower(c.Text)
		n := 0
		for _, w := range words {
			if len([]rune(w)) > 2 && strings.Contains(text, w) {
				n++
			}
		}
		if n > 0 {
			hits = append(hits, scored{c, n})
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].score > hits[j].score })
	out := []guardrailrag.Chunk{}
	for i := 0; i < len(hits) && i < k; i++ {
		out = append(out, hits[i].c)
	}
	return out
}

// generate stands in for the LLM: it answers from the first passage it was given.
func generate(query string, passages []string) string {
	if len(passages) == 0 {
		return "Tôi không có thông tin về câu hỏi này."
	}
	return "Theo tài liệu: " + passages[0]
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	url := env("GUARDRAIL_URL", "http://127.0.0.1:8080")
	guard := guardrailrag.New(url, os.Getenv("GUARDRAIL_CLIENT_KEY"))
	guard.Tenant = "demo-shop"
	idx := &store{}

	// 1. Ingest: every chunk is checked before it is indexed.
	fmt.Println("== 1. Ingest ==")
	files, _ := filepath.Glob(filepath.Join("..", "data", "*.md"))
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		var chunks []guardrailrag.Chunk
		for i, para := range strings.Split(string(raw), "\n\n") {
			if strings.TrimSpace(para) == "" || strings.HasPrefix(para, "# ") {
				continue
			}
			chunks = append(chunks, guardrailrag.Chunk{Text: strings.TrimSpace(para), ChunkID: fmt.Sprintf("%s#%d", filepath.Base(path), i), Source: path})
		}
		doc, err := guard.CheckDocument(ctx, filepath.Base(path), chunks)
		if err != nil {
			log.Fatalf("ingest %s: %v (is the service running at %s?)", path, err, url)
		}
		fmt.Printf("%-24s document: %-7s %s\n", filepath.Base(path), doc.Decision, doc.Reason)
		for _, r := range doc.Chunks {
			for _, v := range r.Violations {
				where := ""
				if len(v.Locations) > 0 {
					where = fmt.Sprintf(" at %d-%d (%s)", v.Locations[0].Start, v.Locations[0].End, v.Locations[0].Kind)
				}
				fmt.Printf("    %-10s %-4s %-7s %s — %s%s\n", r.Ref["chunk_id"], v.Category, v.Action, v.Names["vi"], strings.Join(v.Refs, "; "), where)
			}
			// A held document keeps all its chunks out, even the clean ones.
			if r.Usable && doc.Decision != guardrailrag.Review && doc.Decision != guardrailrag.Remove {
				idx.add(guardrailrag.Chunk{Text: r.Text(), ID: r.ID, Source: fmt.Sprint(r.Ref["source"]), Metadata: r.Metadata})
			}
		}
	}
	fmt.Printf("indexed %d chunks\n\n", len(idx.chunks))

	// 2-4. Query, context, answer for a few questions.
	questions := []string{
		"Chính sách đổi trả trong bao nhiêu ngày?",
		"Số điện thoại của trưởng phòng nhân sự là gì?",
		"Cách chế tạo thuốc nổ tại nhà?",
		"Quần đảo Trường Sa thuộc nước nào?",
	}
	for _, q := range questions {
		fmt.Println("== Q:", q)

		// The query check and the retrieval run together: the check adds almost no latency.
		type queryOut struct {
			r   *guardrailrag.Result
			err error
		}
		checked := make(chan queryOut, 1)
		go func() {
			r, err := guard.CheckQuery(ctx, guardrailrag.QueryRequest{Query: q, UserID: "u-42"})
			checked <- queryOut{r, err}
		}()
		retrieved := idx.search(q, 4)
		qr := <-checked
		if qr.err != nil {
			log.Fatal(qr.err)
		}
		if !qr.r.Usable {
			fmt.Printf("   query %s %v\n   -> %s\n\n", qr.r.Decision, qr.r.Categories(), qr.r.TextForUser())
			continue
		}

		passages, err := guard.FilterContext(ctx, guardrailrag.ContextRequest{Query: q, Chunks: retrieved, Principals: []string{"customer"}})
		if err != nil {
			log.Fatal(err)
		}
		for _, rm := range passages.Removed {
			fmt.Printf("   context removed %s: %s %v\n", rm.ID, rm.Decision, rm.Violations)
		}
		if len(passages.Kept) == 0 && passages.Message != nil {
			fmt.Printf("   -> %s\n\n", *passages.Message)
			continue
		}

		draft := generate(q, passages.Texts())
		answer, err := guard.CheckAnswer(ctx, guardrailrag.AnswerRequest{Answer: draft, Query: q, Context: passages.Kept})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("   answer %s\n   -> %s\n\n", answer.Decision, strings.ReplaceAll(answer.TextForUser(), "\n", "\n      "))
	}

	// 5. The reviewer's side: what is waiting, and whether the audit chain is intact.
	reviewer := guardrailrag.New(url, os.Getenv("GUARDRAIL_REVIEWER_KEY"))
	if list, err := reviewer.Reviews(ctx, "pending", "", 20); err == nil {
		fmt.Printf("== review queue: %v\n", list.Counts)
		for _, it := range list.Items {
			fmt.Printf("   %s %-7s %v\n", it.ID, it.Surface, categoriesOf(it.Violations))
		}
	}
	if v, err := reviewer.VerifyAudit(ctx); err == nil {
		fmt.Printf("== audit chain ok=%v records=%d\n", v.OK, v.Count)
	}
}

func categoriesOf(vs []guardrailrag.Violation) []string {
	out := []string{}
	for _, v := range vs {
		out = append(out, v.Category)
	}
	return out
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
