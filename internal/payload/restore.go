package payload

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"nospyai/internal/redact"
)

// RestoreResponse puts values back into a non-streaming JSON response.
func RestoreResponse(d Dialect, body []byte, v *redact.Vault) ([]byte, error) {
	if !strings.Contains(string(body), "[REDACTED_") {
		return body, nil
	}
	doc, err := decode(body)
	if err != nil {
		return nil, err
	}
	return encode(restoreWalker(d, v).walk(doc, nil, false))
}

func restoreWalker(d Dialect, v *redact.Vault) *walker {
	return &walker{d: d, str: v.Restore, jsonStr: v.RestoreJSONString}
}

// sseEvent is one server-sent event. Unchanged events are written back byte-for-byte.
type sseEvent struct {
	raw     []string       // original lines
	other   []string       // non-data lines (event:, id:, comments)
	data    string         // data lines joined with \n
	obj     map[string]any // data decoded, when it is a JSON object
	changed bool
}

// sseHandler turns one upstream event into the events to send to the client.
type sseHandler func(st *sseState, ev *sseEvent) []*sseEvent

type sseStream struct {
	r     *redact.StreamRestorer
	synth func(rem string) *sseEvent // builds a delta event carrying held-back text
}

type sseState struct {
	w       *walker
	v       *redact.Vault
	streams map[string]*sseStream
	order   []string
	onID    func(id string) // called once, with the response id, when a handler sees it
	idSeen  bool
}

// responseID reports the id of the response being streamed, the first time it is seen.
func (st *sseState) responseID(id string) {
	if id != "" && !st.idSeen && st.onID != nil {
		st.idSeen = true
		st.onID(id)
	}
}

// feed restores one delta of stream id, opening the stream on first use.
func (st *sseState) feed(id string, jsonEscape bool, text string, synth func(string) *sseEvent) string {
	s, ok := st.streams[id]
	if !ok {
		s = &sseStream{r: st.v.NewStreamRestorer(jsonEscape), synth: synth}
		st.streams[id] = s
		st.order = append(st.order, id)
	}
	return s.r.Feed(text)
}

// flush closes stream id and returns a synthetic delta event with any held-back text.
func (st *sseState) flush(id string) []*sseEvent {
	s, ok := st.streams[id]
	if !ok {
		return nil
	}
	delete(st.streams, id)
	if rem := s.r.Flush(); rem != "" {
		return []*sseEvent{s.synth(rem)}
	}
	return nil
}

// flushText closes stream id and returns the text it still held back, for a handler that
// appends it to the event in hand (keeping order) instead of sending a synthetic event.
func (st *sseState) flushText(id string) string {
	s, ok := st.streams[id]
	if !ok {
		return ""
	}
	delete(st.streams, id)
	return s.r.Flush()
}

// openWithPrefix lists the open streams whose id starts with prefix, in opening order.
func (st *sseState) openWithPrefix(prefix string) []string {
	var ids []string
	for _, id := range st.order {
		if _, ok := st.streams[id]; ok && strings.HasPrefix(id, prefix) {
			ids = append(ids, id)
		}
	}
	return ids
}

func (st *sseState) flushAll() []*sseEvent {
	var out []*sseEvent
	for _, id := range st.order {
		out = append(out, st.flush(id)...)
	}
	return out
}

// restore runs the generic restore walk over the event, if it can contain a placeholder.
func (st *sseState) restore(ev *sseEvent) {
	if ev.obj != nil && strings.Contains(ev.data, "[REDACTED_") {
		st.w.walk(ev.obj, nil, false)
		ev.changed = true
	}
}

// NewSSERestorer wraps an SSE response body, restoring placeholders as events stream through.
func NewSSERestorer(d Dialect, body io.ReadCloser, v *redact.Vault) io.ReadCloser {
	return NewSSERestorerWith(d, body, v, nil)
}

// NewSSERestorerWith is NewSSERestorer that also reports the response id (Responses
// chains) to onID, once, as soon as the stream carries it. onID may be nil.
func NewSSERestorerWith(d Dialect, body io.ReadCloser, v *redact.Vault, onID func(id string)) io.ReadCloser {
	pr, pw := io.Pipe()
	st := &sseState{w: restoreWalker(d, v), v: v, streams: map[string]*sseStream{}, onID: onID}
	go func() {
		defer func() { _ = body.Close() }()
		pw.CloseWithError(st.run(d.sse, body, pw))
	}()
	return &sseBody{PipeReader: pr, upstream: body}
}

type sseBody struct {
	*io.PipeReader
	upstream io.Closer
}

func (b *sseBody) Close() error {
	_ = b.PipeReader.Close()
	return b.upstream.Close()
}

func (st *sseState) run(h sseHandler, r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	bw := bufio.NewWriter(w)
	emit := func(evs []*sseEvent) error {
		for _, ev := range evs {
			if err := ev.write(bw); err != nil {
				return err
			}
		}
		return bw.Flush() // one flush per upstream event keeps streaming latency unchanged
	}
	var cur []string
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		eof := err == io.EOF
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			cur = append(cur, line)
		}
		if (line == "" && !eof || eof) && len(cur) > 0 {
			ev := parseEvent(cur)
			cur = nil
			out := []*sseEvent{ev}
			if h != nil {
				out = h(st, ev)
			}
			if err := emit(out); err != nil {
				return err
			}
		}
		if eof {
			return emit(st.flushAll())
		}
	}
}

func parseEvent(lines []string) *sseEvent {
	ev := &sseEvent{raw: lines}
	var data []string
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
		} else {
			ev.other = append(ev.other, l)
		}
	}
	ev.data = strings.Join(data, "\n")
	if len(data) > 0 {
		if v, err := decode([]byte(ev.data)); err == nil {
			ev.obj, _ = v.(map[string]any)
		}
	}
	return ev
}

func (ev *sseEvent) write(w *bufio.Writer) error {
	if !ev.changed {
		for _, l := range ev.raw {
			if _, err := w.WriteString(l); err != nil {
				return err
			}
			if err := w.WriteByte('\n'); err != nil {
				return err
			}
		}
		_, err := w.WriteString("\n")
		return err
	}
	for _, l := range ev.other {
		if _, err := w.WriteString(l); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	b, err := encode(ev.obj)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "data: %s\n\n", b)
	return err
}

// anthropicSSE handles Messages API streaming events. Text and tool-input deltas go through
// a per-block StreamRestorer, because a placeholder can be split across deltas.
func anthropicSSE(st *sseState, ev *sseEvent) []*sseEvent {
	m := ev.obj
	if m == nil {
		return []*sseEvent{ev}
	}
	typ, _ := m["type"].(string)
	idx := m["index"]
	id := fmt.Sprint("block:", idx)
	switch typ {
	case "content_block_delta":
		delta, _ := m["delta"].(map[string]any)
		switch dt, _ := delta["type"].(string); dt {
		case "text_delta":
			anthropicFeed(st, ev, delta, id, idx, dt, "text", false)
		case "input_json_delta":
			anthropicFeed(st, ev, delta, id, idx, dt, "partial_json", true)
		case "thinking_delta", "signature_delta":
			// signed: pass through untouched
		default:
			st.restore(ev)
		}
		return []*sseEvent{ev}
	case "content_block_stop":
		return append(st.flush(id), ev)
	default:
		st.restore(ev)
		return []*sseEvent{ev}
	}
}

func anthropicFeed(st *sseState, ev *sseEvent, delta map[string]any, id string, idx any, dt, field string, jsonEscape bool) {
	in, _ := delta[field].(string)
	synth := func(rem string) *sseEvent {
		return &sseEvent{
			other:   []string{"event: content_block_delta"},
			obj:     map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]any{"type": dt, field: rem}},
			changed: true,
		}
	}
	if out := st.feed(id, jsonEscape, in, synth); out != in {
		delta[field] = out
		ev.changed = true
	}
}
