// Command fakeupstream is a stand-in LLM API for scripts/container-smoke.sh. It answers
// POST /v1/messages (Anthropic Messages shape) with an assistant message that echoes the user text
// it received, so placeholders sent by nospy come back in the response and must be restored. It
// appends one JSON line per request (method, path, header names and the raw body) to --record, which
// is how the smoke test proves the upstream never saw a secret. Test use only: it listens on every
// interface so a container can reach it, and it does no authentication.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type recorded struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Header []string `json:"header_names"`
	Body   string   `json:"body"`
}

func main() {
	listen := flag.String("listen", "0.0.0.0:0", "address to listen on")
	record := flag.String("record", "", "file to append one JSON line per request to (required)")
	portFile := flag.String("port-file", "", "file to write the chosen port to once listening")
	flag.Parse()
	if *record == "" {
		log.Fatal("fakeupstream: --record is required")
	}
	out, err := os.OpenFile(*record, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("fakeupstream: %v", err)
	}
	defer func() {
		if err := out.Close(); err != nil {
			log.Printf("fakeupstream: closing record: %v", err)
		}
	}()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", *listen)
	if err != nil {
		log.Fatalf("fakeupstream: %v", err)
	}
	if *portFile != "" {
		_, port, _ := net.SplitHostPort(ln.Addr().String())
		if err := os.WriteFile(*portFile, []byte(port+"\n"), 0o600); err != nil {
			log.Fatalf("fakeupstream: %v", err)
		}
	}

	var mu sync.Mutex
	log.Fatal((&http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		rec := recorded{Method: r.Method, Path: r.URL.Path, Body: string(body)}
		for k := range r.Header {
			rec.Header = append(rec.Header, strings.ToLower(k))
		}
		sort.Strings(rec.Header)
		line, _ := json.Marshal(rec)
		mu.Lock()
		_, err := out.Write(append(line, '\n'))
		mu.Unlock()
		if err != nil {
			log.Printf("fakeupstream: recording request: %v", err)
			http.Error(w, "recording request failed", http.StatusInternalServerError)
			return
		}

		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_fake", "type": "message", "role": "assistant", "model": "fake",
			"content":     []map[string]any{{"type": "text", "text": "You said: " + userText(body)}},
			"stop_reason": "end_turn",
			"usage":       map[string]int{"input_tokens": 1, "output_tokens": 1},
		}); err != nil {
			log.Printf("fakeupstream: writing response: %v", err)
		}
	})}).Serve(ln))
}

// userText joins the text of every message in a Messages API request body.
func userText(body []byte) string {
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &req) != nil {
		return "(unparseable request)"
	}
	var parts []string
	for _, m := range req.Messages {
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			parts = append(parts, s)
			continue
		}
		var blocks []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(m.Content, &blocks) == nil {
			for _, b := range blocks {
				parts = append(parts, b.Text)
			}
		}
	}
	return strings.Join(parts, "\n")
}
