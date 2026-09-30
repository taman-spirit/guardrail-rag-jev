// Package guardrailrag is the Go client for the guardrail-rag-jev service.
//
// The service checks RAG content at four points and returns a decision for each:
//
//	client := guardrailrag.New("http://guardrail:8080", os.Getenv("GUARDRAIL_CLIENT_KEY"))
//
//	results, _ := client.CheckDocuments(ctx, chunks)          // ingest: before indexing
//	query, _ := client.CheckQuery(ctx, guardrailrag.QueryRequest{Query: q})
//	passages, _ := client.FilterContext(ctx, guardrailrag.ContextRequest{Query: q, Chunks: retrieved})
//	answer, _ := client.CheckAnswer(ctx, guardrailrag.AnswerRequest{Answer: a, Query: q, Context: passages.Kept})
//
// Every Result carries a Decision (pass, redact, review, remove), the text to use, and every
// violation found with its legal or standard basis and, where known, its location in the text.
package guardrailrag

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one guardrail service.
type Client struct {
	BaseURL string
	APIKey  string
	// Tenant and Profile are sent as X-Guardrail-Tenant and X-Guardrail-Profile. A key bound to a
	// tenant on the server overrides them.
	Tenant  string
	Profile string
	HTTP    *http.Client
}

// New returns a client with a 10-second timeout.
func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// APIError is a non-2xx answer from the service.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("guardrail: HTTP %d: %s", e.Status, e.Body) }

// CheckDocuments checks chunks before they are indexed. Index only results where Usable is true,
// using Result.Text() and writing Result.Metadata next to the chunk.
func (c *Client) CheckDocuments(ctx context.Context, chunks []Chunk) ([]Result, error) {
	var out struct {
		Results []Result `json:"results"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/ingest", map[string]any{"documents": chunks}, &out)
	return out.Results, err
}

// CheckDocument checks every chunk of one document and rolls them up into one decision. A chunk
// with injected instructions or malicious content holds the whole document.
func (c *Client) CheckDocument(ctx context.Context, docID string, chunks []Chunk) (*DocumentResult, error) {
	var out DocumentResult
	err := c.do(ctx, http.MethodPost, "/v1/ingest", map[string]any{"doc_id": docID, "documents": chunks}, &out)
	return &out, err
}

// SubmitJob checks a large ingest batch in the background. Poll Job, or pass a callbackURL to be
// told when it is done.
func (c *Client) SubmitJob(ctx context.Context, chunks []Chunk, callbackURL string) (string, error) {
	var out struct {
		JobID string `json:"job_id"`
	}
	body := map[string]any{"documents": chunks}
	if callbackURL != "" {
		body["callback_url"] = callbackURL
	}
	err := c.do(ctx, http.MethodPost, "/v1/ingest/jobs", body, &out)
	return out.JobID, err
}

// Job returns an ingest job's progress and, once done, its results.
func (c *Client) Job(ctx context.Context, jobID string) (*Job, error) {
	var out Job
	err := c.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(jobID), nil, &out)
	return &out, err
}

// WaitJob polls until the job is done or failed, or ctx ends.
func (c *Client) WaitJob(ctx context.Context, jobID string, every time.Duration) (*Job, error) {
	for {
		job, err := c.Job(ctx, jobID)
		if err != nil || job.Status == "done" || job.Status == "failed" {
			return job, err
		}
		select {
		case <-ctx.Done():
			return job, ctx.Err()
		case <-time.After(every):
		}
	}
}

// CheckQuery checks a user question before it is answered. When Usable is false, show
// Result.TextForUser() instead of answering.
func (c *Client) CheckQuery(ctx context.Context, req QueryRequest) (*Result, error) {
	var out Result
	err := c.do(ctx, http.MethodPost, "/v1/query", req, &out)
	return &out, err
}

// FilterContext checks retrieved passages and returns the ones to give the model.
func (c *Client) FilterContext(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	var out ContextResult
	err := c.do(ctx, http.MethodPost, "/v1/context", req, &out)
	return &out, err
}

// CheckAnswer checks a generated answer before it is shown. Show Result.TextForUser().
func (c *Client) CheckAnswer(ctx context.Context, req AnswerRequest) (*Result, error) {
	var out Result
	err := c.do(ctx, http.MethodPost, "/v1/answer", req, &out)
	return &out, err
}

// Reviews lists the review queue (reviewer key). status "" lists every status.
func (c *Client) Reviews(ctx context.Context, status, surface string, limit int) (*ReviewList, error) {
	q := url.Values{"status": {status}}
	if surface != "" {
		q.Set("surface", surface)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var out ReviewList
	err := c.do(ctx, http.MethodGet, "/v1/reviews?"+q.Encode(), nil, &out)
	return &out, err
}

// DecideReview approves, rejects or edits a held item (reviewer key). The decision also settles
// the same text next time it is checked.
func (c *Client) DecideReview(ctx context.Context, reviewID, decision, note, content string) (*ReviewItem, error) {
	body := map[string]any{"decision": decision, "note": note}
	if content != "" {
		body["content"] = content
	}
	var out ReviewItem
	err := c.do(ctx, http.MethodPost, "/v1/reviews/"+url.PathEscape(reviewID)+"/decision", body, &out)
	return &out, err
}

// VerifyAudit walks the audit hash chain (reviewer key).
func (c *Client) VerifyAudit(ctx context.Context) (*AuditVerification, error) {
	var out AuditVerification
	err := c.do(ctx, http.MethodGet, "/v1/audit/verify", nil, &out)
	return &out, err
}

// Policy returns the effective policy: packs, categories, thresholds and rules.
func (c *Client) Policy(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodGet, "/v1/policy", nil, &out)
	return out, err
}

// UpdatePolicy switches packs or categories on or off at runtime (admin key).
func (c *Client) UpdatePolicy(ctx context.Context, change PolicyChange) (map[string]any, error) {
	var out map[string]any
	err := c.do(ctx, http.MethodPatch, "/v1/policy", change, &out)
	return out, err
}

// VerifySignature checks the X-Guardrail-Signature header of a webhook the service sent.
func VerifySignature(secret string, body []byte, header string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(header))
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "guardrail-rag-jev-go/0.1")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.Tenant != "" {
		req.Header.Set("X-Guardrail-Tenant", c.Tenant)
	}
	if c.Profile != "" {
		req.Header.Set("X-Guardrail-Profile", c.Profile)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &APIError{Status: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
