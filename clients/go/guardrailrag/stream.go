package guardrailrag

import (
	"context"
	"net/http"
	"net/url"
)

// AnswerStream guards an answer while the model streams it. Feed each token or delta, act on the
// events it returns, then call Finish.
//
// Sessions live on one service instance: send a stream's requests to the same instance.
type AnswerStream struct {
	client *Client
	ID     string
}

// StartAnswerStream opens a guarded stream.
func (c *Client) StartAnswerStream(ctx context.Context, req AnswerStreamRequest) (*AnswerStream, error) {
	var out struct {
		StreamID string `json:"stream_id"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/answer/streams", req, &out); err != nil {
		return nil, err
	}
	return &AnswerStream{client: c, ID: out.StreamID}, nil
}

// Feed sends newly generated text and returns what may be shown now.
func (s *AnswerStream) Feed(ctx context.Context, text string) ([]StreamEvent, error) {
	var out struct {
		Events []StreamEvent `json:"events"`
	}
	err := s.client.do(ctx, http.MethodPost, "/v1/answer/streams/"+url.PathEscape(s.ID)+"/chunks", map[string]string{"text": text}, &out)
	return out.Events, err
}

// Finish checks the remainder and the complete answer. The last event is "done" unless the
// stream was stopped.
func (s *AnswerStream) Finish(ctx context.Context) ([]StreamEvent, error) {
	var out struct {
		Events []StreamEvent `json:"events"`
	}
	err := s.client.do(ctx, http.MethodPost, "/v1/answer/streams/"+url.PathEscape(s.ID)+"/finish", nil, &out)
	return out.Events, err
}
