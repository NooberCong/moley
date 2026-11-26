// Package rpc is Moley's control protocol: JSON messages, each prefixed by
// its length as a 4-byte little-endian integer. That is exactly Chrome's
// native messaging framing, so the browser host is a plain relay.
//
//	request:  {"id": 1, "method": "status", "params": {...}}
//	response: {"id": 1, "result": {...}} | {"id": 1, "error": {...}}
//	event:    {"id": 1, "event": "status", "result": {...}}
//
// Events are pushed for a long-running request (events.subscribe) until the
// client closes the connection; they carry that request's id.
package rpc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const MaxFrame = 16 << 20

type Request struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Event  string          `json:"event,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

type emitKey struct{}

// Emit pushes an event to the client of the request ctx belongs to. It
// fails once the client is gone.
func Emit(ctx context.Context, event string, data any) error {
	emit, ok := ctx.Value(emitKey{}).(func(string, any) error)
	if !ok {
		return errors.New("rpc: no client to emit to")
	}
	return emit(event, data)
}

// Error is the wire error. Code is a stable snake_case identifier that
// scripts can branch on; Hint says what to do about it.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Errorf builds a coded error.
func Errorf(code, hint, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...), Hint: hint}
}

// Common codes.
const (
	CodeInvalidParams = "invalid_params"
	CodeNotFound      = "not_found"
	CodeUnknownMethod = "unknown_method"
	CodeConfirm       = "confirmation_required"
	CodeInternal      = "internal"
	CodeCheckFailed   = "check_failed"
)

func ReadFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}
	if n > MaxFrame {
		return nil, fmt.Errorf("frame too large: %d bytes", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func WriteFrame(w io.Writer, b []byte) error {
	buf := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// Handler serves one request. peer describes the connection's client.
type Handler func(ctx context.Context, peer any, method string, params json.RawMessage) (any, error)

// Serve handles requests on conn until it closes. Requests run
// concurrently (a long "wait" doesn't block others); responses are
// written whole, in completion order, matched by id.
func Serve(ctx context.Context, conn net.Conn, peer any, h Handler) {
	ctx, cancel := context.WithCancel(ctx)
	var wmu sync.Mutex
	var wg sync.WaitGroup
	// When the client goes away, cancel its in-flight calls (a long wait,
	// say) first, then wait for them.
	defer func() {
		cancel()
		conn.Close()
		wg.Wait()
	}()
	for {
		frame, err := ReadFrame(conn)
		if err != nil {
			return
		}
		var req Request
		if err := json.Unmarshal(frame, &req); err != nil || req.Method == "" {
			_ = writeResponse(conn, &wmu, Response{Error: Errorf(CodeInvalidParams, "", "malformed request")})
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := Response{ID: req.ID}
			rctx := context.WithValue(ctx, emitKey{}, func(event string, data any) error {
				b, err := json.Marshal(data)
				if err != nil {
					return err
				}
				return writeResponse(conn, &wmu, Response{ID: req.ID, Event: event, Result: b})
			})
			out, err := h(rctx, peer, req.Method, req.Params)
			if err != nil {
				var re *Error
				if !errors.As(err, &re) {
					re = &Error{Code: CodeInternal, Message: err.Error()}
				}
				res.Error = re
			} else if res.Result, err = json.Marshal(out); err != nil {
				res.Error = &Error{Code: CodeInternal, Message: err.Error()}
			}
			_ = writeResponse(conn, &wmu, res)
		}()
	}
}

func writeResponse(w io.Writer, mu *sync.Mutex, res Response) error {
	b, _ := json.Marshal(res)
	mu.Lock()
	defer mu.Unlock()
	return WriteFrame(w, b)
}

// Client is a single-connection, sequential client (the CLI makes one
// call per process).
type Client struct {
	conn net.Conn
	mu   sync.Mutex
	next int
}

func NewClient(conn net.Conn) *Client { return &Client{conn: conn} }

func (c *Client) Close() error { return c.conn.Close() }

// Call sends method(params) and decodes the result into out (if non-nil).
// A daemon-side failure is returned as *Error.
func (c *Client) Call(ctx context.Context, method string, params, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, _ := json.Marshal(Request{ID: json.RawMessage(fmt.Sprint(c.next)), Method: method, Params: p})
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
		defer c.conn.SetDeadline(time.Time{})
	}
	if err := WriteFrame(c.conn, req); err != nil {
		return err
	}
	frame, err := ReadFrame(c.conn)
	if err != nil {
		return err
	}
	var res Response
	if err := json.Unmarshal(frame, &res); err != nil {
		return err
	}
	if res.Error != nil {
		return res.Error
	}
	if out != nil && len(res.Result) > 0 {
		return json.Unmarshal(res.Result, out)
	}
	return nil
}

// Subscribe calls a streaming method and hands each event to fn until ctx
// ends, the daemon ends the stream, or fn returns an error. It holds the
// connection for its whole duration: use a separate client for calls.
func (c *Client) Subscribe(ctx context.Context, method string, params any, fn func(event string, data json.RawMessage) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, _ := json.Marshal(Request{ID: json.RawMessage(`"sub"`), Method: method, Params: p})
	if err := WriteFrame(c.conn, req); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		frame, err := ReadFrame(c.conn)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var res Response
		if err := json.Unmarshal(frame, &res); err != nil {
			return err
		}
		switch {
		case res.Error != nil:
			return res.Error
		case res.Event == "":
			return nil // the stream ended
		}
		if err := fn(res.Event, res.Result); err != nil {
			return err
		}
	}
}
