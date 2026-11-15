package waf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/TheAlsaadi/SoireeHost/internal/fwevent"
)

// eventLogger is where events go: the handler's Caddy logger.
type eventLogger = *zap.Logger

var (
	errBlocked = errors.New("request blocked by the firewall")
	errBusy    = errors.New("the firewall is busy inspecting other requests")
)

// TextInspectBytes is how much body text (forms, JSON, XML, anything that is
// not a multipart file) the firewall inspects. The rules cost about 12 s of
// CPU per MB of text, so a body with more text is refused with 413 in Block
// mode and inspected only up to this size in Detect only (owner decision of
// 15 Nov 2026; ModSecurity's SecRequestBodyNoFilesLimit, which Coraza parses
// but does not enforce).
const TextInspectBytes int64 = 128 << 10

// SoireeHost's own limit rules, reported in events like CRS rules.
const (
	RuleTextLimit = 100001
	RuleBodyLimit = 100002
)

// inspectWait bounds the wait for an inspection slot (a variable for tests).
var inspectWait = 10 * time.Second

// slots caps the inspections running at once, so requests built to cost the
// most CPU can never take every core: serving and the other roles keep at
// least half of them (ADR-0008).
var slots = semaphore.NewWeighted(int64(max(2, runtime.NumCPU()/2)))

// evaluate runs one rule phase while holding an inspection slot. Slots are
// held only while rules run, never while the body arrives from the network,
// so slow uploads cannot hold them (pre-merge review, 15 Nov 2026).
func evaluate[T any](r *http.Request, phase func() T) (T, error) {
	ctx, cancel := context.WithTimeout(r.Context(), inspectWait)
	defer cancel()
	if err := slots.Acquire(ctx, 1); err != nil {
		var zero T
		return zero, errBusy
	}
	defer slots.Release(1)
	return phase(), nil
}

type bodyResult struct {
	it  *types.Interruption
	err error
}

// limitHit is a refusal for size, with the rule it is reported as.
type limitHit struct {
	rule fwevent.Rule
}

func textLimitHit() *limitHit {
	return &limitHit{rule: fwevent.Rule{ID: RuleTextLimit, Severity: "notice",
		Msg: fmt.Sprintf("Request body text larger than %d KB", TextInspectBytes>>10)}}
}

func tooMuchText() *types.Interruption {
	return &types.Interruption{RuleID: RuleTextLimit, Action: "deny", Status: http.StatusRequestEntityTooLarge}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (f Firewall) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if n := reserve(r); n > 0 {
		if !budget.TryAcquire(n) {
			w.Header().Set("Retry-After", "5")
			return caddyhttp.Error(http.StatusServiceUnavailable, errBusy)
		}
		defer budget.Release(n)
	}
	tx := f.waf.NewTransaction()
	it, hit, perr := f.process(tx, r)
	status := 0
	defer func() {
		tx.ProcessLogging()
		f.record(tx, r, status, hit)
		_ = tx.Close()
	}()
	if errors.Is(perr, errBusy) {
		w.Header().Set("Retry-After", "5")
		return caddyhttp.Error(http.StatusServiceUnavailable, errBusy)
	}
	if perr != nil {
		var tooBig *http.MaxBytesError
		if errors.As(perr, &tooBig) {
			// the site's own body limit, applied before the firewall
			return caddyhttp.Error(http.StatusRequestEntityTooLarge, perr)
		}
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("reading the request: %w", perr))
	}
	if it != nil {
		status = blockStatus(it)
		if status == http.StatusRequestEntityTooLarge && hit == nil {
			hit = &limitHit{rule: fwevent.Rule{ID: RuleBodyLimit, Severity: "notice",
				Msg: fmt.Sprintf("Request body larger than %d MB", InspectBytes>>20)}}
		}
		return caddyhttp.Error(status, errBlocked)
	}
	return next.ServeHTTP(w, r)
}

// reserve is how much of the body budget a request takes: its length up to
// InspectBytes, all of InspectBytes when the length is unknown, nothing when
// it has no body.
func reserve(r *http.Request) int64 {
	switch {
	case !hasBody(r):
		return 0
	case r.ContentLength < 0 || r.ContentLength > InspectBytes:
		return InspectBytes
	default:
		return r.ContentLength
	}
}

func hasBody(r *http.Request) bool {
	return r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}

// blockStatus is the status a block answers with: a rule's own 400 or 413,
// otherwise 403. A rule's redirect or drop is a 403 too; no rule-supplied
// URL is ever used.
func blockStatus(it *types.Interruption) int {
	if it.Action == "deny" && (it.Status == http.StatusBadRequest || it.Status == http.StatusRequestEntityTooLarge) {
		return it.Status
	}
	return http.StatusForbidden
}

// process runs the request phases: connection, URI, headers and body. The
// body is buffered in memory (at most InspectBytes, and at most
// TextInspectBytes of text) and handed on intact.
func (f Firewall) process(tx types.Transaction, r *http.Request) (*types.Interruption, *limitHit, error) {
	client, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	tx.ProcessConnection(client, 0, "", 0)
	tx.ProcessURI(r.RequestURI, r.Method, r.Proto)
	for k, vs := range r.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	// net/http removes Transfer-Encoding from the headers; rules that look
	// for smuggling need it back
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}
	it, err := evaluate(r, tx.ProcessRequestHeaders)
	if err != nil || it != nil {
		return it, nil, err
	}
	if !tx.IsRequestBodyAccessible() || !hasBody(r) {
		return processBody(r, tx)
	}
	boundary, isMultipart := multipartBoundary(r.Header.Get("Content-Type"))
	block := f.Mode == ModeBlock

	src := io.Reader(r.Body)
	if !isMultipart {
		if block && r.ContentLength > TextInspectBytes {
			return tooMuchText(), textLimitHit(), nil
		}
		// one byte more than the limit tells Block mode the body is over
		// it; Detect only inspects the first TextInspectBytes
		n := TextInspectBytes
		if block {
			n++
		}
		src = io.LimitReader(r.Body, n)
	}
	// buffering only: no rule runs here, so no slot is held while the body
	// arrives
	it, n, err := tx.ReadRequestBodyFrom(src)
	if err != nil {
		return nil, nil, err
	}
	if it != nil {
		return it, nil, nil
	}
	if block && !isMultipart && int64(n) > TextInspectBytes {
		return tooMuchText(), textLimitHit(), nil
	}
	if isMultipart {
		// file contents cost little, but text fields are inspected like any
		// other text: count them before the rules see them
		buffered, err := tx.RequestBodyReader()
		if err != nil {
			return nil, nil, err
		}
		if multipartTextOver(buffered, boundary, TextInspectBytes) {
			if block {
				return tooMuchText(), textLimitHit(), nil
			}
			// Detect only: this body is not inspected and goes on whole
			if err := chainBody(tx, r); err != nil {
				return nil, nil, err
			}
			return nil, nil, nil
		}
	}
	if err := chainBody(tx, r); err != nil {
		return nil, nil, err
	}
	return processBody(r, tx)
}

// processBody runs the body phase under an inspection slot.
func processBody(r *http.Request, tx types.Transaction) (*types.Interruption, *limitHit, error) {
	res, err := evaluate(r, func() bodyResult {
		it, err := tx.ProcessRequestBody()
		return bodyResult{it, err}
	})
	if err != nil {
		return nil, nil, err
	}
	return res.it, nil, res.err
}

// chainBody hands the site the body the firewall buffered, followed by
// whatever it did not read (Detect only, over its limits).
func chainBody(tx types.Transaction, r *http.Request) error {
	buffered, err := tx.RequestBodyReader()
	if err != nil {
		return err
	}
	r.Body = readCloser{Reader: io.MultiReader(buffered, r.Body), Closer: r.Body}
	return nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// blockingRules are the rules that block in Block mode: CRS's inbound
// anomaly evaluation and the body parsing rules from Coraza's recommended
// configuration. In Detect only, a match of one of them is an event.
var blockingRules = map[int]bool{949110: true, 949111: true, 200002: true, 200003: true, 200004: true, 200005: true, 200009: true}

// record writes one event for a request the firewall blocked, or in Detect
// only would have blocked.
func (f Firewall) record(tx types.Transaction, r *http.Request, status int, hit *limitHit) {
	matched := tx.MatchedRules()
	action := fwevent.ActionBlocked
	if f.Mode == ModeDetect {
		action, status = fwevent.ActionDetected, 0
		would := false
		for _, mr := range matched {
			if blockingRules[mr.Rule().ID()] {
				would = true
				break
			}
		}
		if !would {
			return
		}
	} else if status == 0 {
		return
	}
	client, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	ev := fwevent.Event{
		Time: time.Now(), Site: f.Site, Mode: f.Mode, Action: action, Status: status,
		ParanoiaLevel: f.ParanoiaLevel, Method: r.Method, Host: r.Host, URI: r.RequestURI, ClientIP: client,
	}
	if hit != nil {
		ev.Rules = append(ev.Rules, hit.rule)
	}
	var values []string
	for _, mr := range matched {
		id := mr.Rule().ID()
		if mr.Message() == "" || (id >= 900000 && id <= 901999) {
			continue // setup and scoring rules
		}
		rule := fwevent.Rule{ID: id, Severity: mr.Rule().Severity().String(), Msg: mr.Message()}
		for _, md := range mr.MatchedDatas() {
			rule.Where = append(rule.Where, md.Variable().Name())
			values = append(values, md.Value(), md.Data(), md.Key())
		}
		values = append(values, mr.Data())
		ev.Rules = append(ev.Rules, rule)
	}
	f.logger.Warn(fwevent.LogMessage, zap.Any("event", ev.Clean(values)))
}

var _ caddyhttp.MiddlewareHandler = (*Firewall)(nil)
