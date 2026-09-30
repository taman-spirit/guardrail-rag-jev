package guardrailrag

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, handler func(path string, body map[string]any, r *http.Request) (int, any)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		status, out := handler(r.URL.Path, body, r)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "key")
	c.Tenant = "bank"
	return c
}

func TestCheckQuerySendsKeyTenantAndDecodesTheResult(t *testing.T) {
	msg := "Mình không thể hỗ trợ yêu cầu này."
	c := serve(t, func(path string, body map[string]any, r *http.Request) (int, any) {
		if path != "/v1/query" || body["query"] != "q" || r.Header.Get("Authorization") != "Bearer key" || r.Header.Get("X-Guardrail-Tenant") != "bank" {
			t.Errorf("unexpected request %s %v %v", path, body, r.Header)
		}
		return 200, map[string]any{
			"id": "chk_1", "surface": "query", "decision": "remove", "usable": false, "message": msg,
			"violations": []any{
				map[string]any{"category": "iwp", "action": "block", "refs": []string{"AILuminate iwp"}},
				map[string]any{"category": "vsv", "action": "block", "refs": []string{"Luật An ninh mạng 2025"},
					"locations": []any{map[string]any{"start": 10, "end": 40, "kind": "segment"}}},
			},
		}
	})
	r, err := c.CheckQuery(context.Background(), QueryRequest{Query: "q"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Decision != Remove || r.Usable || r.TextForUser() != msg {
		t.Fatalf("got %+v", r)
	}
	if cats := r.Categories(); len(cats) != 2 || cats[1] != "vsv" || r.Violations[1].Locations[0].End != 40 {
		t.Fatalf("violations %+v", r.Violations)
	}
}

func TestTextForUserAppendsNotices(t *testing.T) {
	content := "Được hoàn tiền trong 30 ngày."
	r := Result{Usable: true, Content: &content, Notices: []string{"Nội dung này do AI tạo ra."}}
	if r.TextForUser() != content+"\n\nNội dung này do AI tạo ra." {
		t.Fatal(r.TextForUser())
	}
}

func TestFilterContext(t *testing.T) {
	c := serve(t, func(path string, body map[string]any, r *http.Request) (int, any) {
		if len(body["chunks"].([]any)) != 2 {
			t.Error("chunks not sent")
		}
		return 200, map[string]any{"kept": []any{map[string]any{"id": "a", "text": "ok"}},
			"removed": []any{map[string]any{"id": "b", "decision": "remove", "violations": []string{"ipi"}}}}
	})
	res, err := c.FilterContext(context.Background(), ContextRequest{Query: "q", Chunks: []Chunk{{ID: "a", Text: "ok"}, {ID: "b", Text: "x"}}})
	if err != nil || len(res.Texts()) != 1 || res.Removed[0].Violations[0] != "ipi" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestAPIErrors(t *testing.T) {
	c := serve(t, func(string, map[string]any, *http.Request) (int, any) { return 403, map[string]any{"detail": "no"} })
	_, err := c.UpdatePolicy(context.Background(), PolicyChange{Packs: map[string]bool{"vn-ai": false}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("got %v", err)
	}
}

func TestVerifySignatureMatchesThePythonService(t *testing.T) {
	body := []byte(`{"event":"review.decided"}`)
	// hmac.new(b"secret", body, hashlib.sha256).hexdigest(), as the service signs it
	header := "sha256=c1111e96b3a8868186208d2518f7046118be78fc9ae510c28612729f2679ed8e"
	if !VerifySignature("secret", body, header) {
		t.Fatal("the service's signature did not verify")
	}
	if VerifySignature("other", body, header) || VerifySignature("secret", []byte("{}"), header) {
		t.Fatal("a wrong secret or body verified")
	}
}
