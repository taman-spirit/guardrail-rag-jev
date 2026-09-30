package guardrailrag

// Decision is what to do with a piece of content.
type Decision string

const (
	// Pass: use the content as it is (notices may be attached).
	Pass Decision = "pass"
	// Redact: use Result.Content, where sensitive spans are masked.
	Redact Decision = "redact"
	// Review: held; it waits in the review queue and is not used until a person approves it.
	Review Decision = "review"
	// Remove: dropped. A query or an answer is replaced by Result.Message.
	Remove Decision = "remove"
)

// Location says where in the content a violation was seen.
type Location struct {
	Start       int      `json:"start"`
	End         int      `json:"end"`
	Kind        string   `json:"kind"` // "segment" or "detector:<name>"
	Excerpt     string   `json:"excerpt,omitempty"`
	Probability *float64 `json:"probability,omitempty"`
}

// Violation is one category that fired, with its basis.
type Violation struct {
	Category    string            `json:"category"`
	Name        string            `json:"name"`
	Names       map[string]string `json:"names"`
	Pack        string            `json:"pack"`
	Action      string            `json:"action"` // flag, review, block
	Probability float64           `json:"probability"`
	Confidence  float64           `json:"confidence"`
	Severity    float64           `json:"severity"`
	Refs        []string          `json:"refs"` // the law or standard it maps to
	Source      string            `json:"source"`
	Notes       []string          `json:"notes"`
	Locations   []Location        `json:"locations,omitempty"`
}

// Redaction is one masked span. Offsets refer to the original text.
type Redaction struct {
	Detector    string `json:"detector"`
	Category    string `json:"category"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Replacement string `json:"replacement"`
}

// Verdict is the policy decision behind a result.
type Verdict struct {
	Action       string         `json:"action"`
	Route        string         `json:"route"`
	Surface      string         `json:"surface"`
	Confidence   float64        `json:"confidence"`
	Severity     float64        `json:"severity"`
	Signals      map[string]any `json:"signals"`
	AppliedRules []string       `json:"applied_rules"`
	PolicyID     string         `json:"policy_id"`
	Model        string         `json:"model"`
	LatencyMS    float64        `json:"latency_ms"`
	Degraded     bool           `json:"degraded"`
	Cached       bool           `json:"cached"`
	Error        *string        `json:"error"`
}

// Result is the answer for one piece of content.
type Result struct {
	ID            string         `json:"id"`
	Surface       string         `json:"surface"`
	Decision      Decision       `json:"decision"`
	Usable        bool           `json:"usable"`
	Content       *string        `json:"content"`
	Language      string         `json:"language"`
	Message       *string        `json:"message"`
	Notices       []string       `json:"notices"`
	Violations    []Violation    `json:"violations"`
	Redactions    []Redaction    `json:"redactions"`
	ReviewID      *string        `json:"review_id"`
	Override      *string        `json:"override"`
	Reason        string         `json:"reason"`
	WouldDecision *Decision      `json:"would_decision"`
	Metadata      map[string]any `json:"metadata"`
	Provider      string         `json:"provider"`
	Ref           map[string]any `json:"ref"`
	Verdict       Verdict        `json:"verdict"`
}

// Text is the content to use, or "" when it was held or removed.
func (r Result) Text() string {
	if r.Content == nil {
		return ""
	}
	return *r.Content
}

// TextForUser is what to show for a query or an answer: the prewritten reply when the content was
// withheld, otherwise the content followed by its notices (disclaimer, AI label, affirmation).
func (r Result) TextForUser() string {
	if !r.Usable {
		if r.Message != nil {
			return *r.Message
		}
		return ""
	}
	out := r.Text()
	for _, n := range r.Notices {
		out += "\n\n" + n
	}
	return out
}

// Categories lists the violated categories.
func (r Result) Categories() []string {
	out := make([]string, 0, len(r.Violations))
	for _, v := range r.Violations {
		out = append(out, v.Category)
	}
	return out
}

// Chunk is a document chunk or a retrieved passage.
type Chunk struct {
	Text     string         `json:"text"`
	ID       string         `json:"id,omitempty"`
	DocID    string         `json:"doc_id,omitempty"`
	ChunkID  string         `json:"chunk_id,omitempty"`
	Source   string         `json:"source,omitempty"`
	Title    string         `json:"title,omitempty"`
	Trust    string         `json:"trust,omitempty"` // trusted, internal, untrusted
	ACL      []string       `json:"acl,omitempty"`   // who may read it, for the ACL cross-check
	Score    *float64       `json:"score,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DocumentResult rolls a document's chunks up into one decision.
type DocumentResult struct {
	DocID      string              `json:"doc_id"`
	Decision   Decision            `json:"decision"`
	Reason     string              `json:"reason"`
	Violations map[string][]string `json:"violations"` // category -> chunk ids
	Chunks     []Result            `json:"chunks"`
}

// RemovedChunk is a retrieved passage that was not given to the model.
type RemovedChunk struct {
	ID         string   `json:"id"`
	DocID      string   `json:"doc_id"`
	Source     string   `json:"source"`
	Decision   Decision `json:"decision"`
	Violations []string `json:"violations"`
	Reason     string   `json:"reason"`
	CheckID    string   `json:"check_id"`
	ReviewID   *string  `json:"review_id"`
}

// ContextResult is the retrieved passages after filtering.
type ContextResult struct {
	Kept    []Chunk        `json:"kept"`
	Removed []RemovedChunk `json:"removed"`
	Message *string        `json:"message"` // set when nothing usable is left
	Results []Result       `json:"results"`
}

// Texts returns the text of every kept passage, masked where needed.
func (c ContextResult) Texts() []string {
	out := make([]string, 0, len(c.Kept))
	for _, k := range c.Kept {
		out = append(out, k.Text)
	}
	return out
}

// QueryRequest is a user question to check.
type QueryRequest struct {
	Query     string         `json:"query"`
	UserID    string         `json:"user_id,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Language  string         `json:"language,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// ContextRequest is a set of retrieved passages to filter.
type ContextRequest struct {
	Query      string   `json:"query,omitempty"`
	Chunks     []Chunk  `json:"chunks"`
	Principals []string `json:"principals,omitempty"`
	Language   string   `json:"language,omitempty"`
}

// AnswerRequest is a generated answer to check.
type AnswerRequest struct {
	Answer   string         `json:"answer"`
	Query    string         `json:"query,omitempty"`
	Context  []Chunk        `json:"context,omitempty"`
	Language string         `json:"language,omitempty"`
	Partial  bool           `json:"partial,omitempty"` // a streamed answer still being written
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ReviewItem is one entry of the review queue.
type ReviewItem struct {
	ID           string         `json:"id"`
	Status       string         `json:"status"` // pending, approved, rejected, edited
	Surface      string         `json:"surface"`
	Scope        string         `json:"scope"`
	ContentHash  string         `json:"content_hash"`
	Content      *string        `json:"content"`
	Language     string         `json:"language"`
	Decision     string         `json:"decision"`
	Reason       string         `json:"reason"`
	Violations   []Violation    `json:"violations"`
	Ref          map[string]any `json:"ref"`
	Tenant       string         `json:"tenant"`
	CheckID      string         `json:"check_id"`
	DecidedBy    *string        `json:"decided_by"`
	DecidedAt    *string        `json:"decided_at"`
	Note         *string        `json:"note"`
	FinalContent *string        `json:"final_content"`
	CreatedAt    string         `json:"created_at"`
}

// ReviewList is a page of the review queue.
type ReviewList struct {
	Items  []ReviewItem   `json:"items"`
	Counts map[string]int `json:"counts"`
}

// JobResult is one chunk's outcome in an ingest job.
type JobResult struct {
	CheckID    string         `json:"check_id"`
	Ref        map[string]any `json:"ref"`
	Decision   Decision       `json:"decision"`
	Content    *string        `json:"content"`
	ReviewID   *string        `json:"review_id"`
	Violations []struct {
		Category string `json:"category"`
		Action   string `json:"action"`
		Name     string `json:"name"`
	} `json:"violations"`
	Metadata map[string]any `json:"metadata"`
}

// Job is an asynchronous ingest check.
type Job struct {
	ID      string         `json:"id"`
	Status  string         `json:"status"` // queued, running, done, failed
	Total   int            `json:"total"`
	Done    int            `json:"done"`
	Summary map[string]int `json:"summary"`
	Results []JobResult    `json:"results"`
	Error   *string        `json:"error"`
}

// AuditVerification is the result of walking the audit chain.
type AuditVerification struct {
	OK       bool   `json:"ok"`
	Count    int    `json:"count"`
	Head     string `json:"head,omitempty"`
	BrokenAt *int   `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// PolicyChange switches packs and categories at runtime (admin key).
type PolicyChange struct {
	Packs      map[string]bool           `json:"packs,omitempty"`
	Categories map[string]map[string]any `json:"categories,omitempty"`
}
