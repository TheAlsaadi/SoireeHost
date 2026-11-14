package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// makeToken builds a token in cloudflared's format with a secret of n bytes.
func makeToken(t testing.TB, fields map[string]any) string {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func goodFields() map[string]any {
	return map[string]any{
		"a": "0123456789abcdef0123456789abcdef",
		"t": "6ff42ae2-765d-4adf-8112-31c55c1551ef",
		"s": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))),
	}
}

// TestTunnelTokenFormat is the S-50 check: only a tunnel token is accepted.
func TestTunnelTokenFormat(t *testing.T) {
	good := makeToken(t, goodFields())
	parts, err := ValidateTunnelToken(good)
	if err != nil {
		t.Fatalf("good token refused: %v", err)
	}
	if parts.AccountTag != "0123456789abcdef0123456789abcdef" || parts.Secret == "" {
		t.Fatalf("parts = %+v", parts)
	}
	withE := goodFields()
	withE["e"] = "fed"
	if _, err := ValidateTunnelToken(makeToken(t, withE)); err != nil {
		t.Fatalf("token with endpoint refused: %v", err)
	}

	mut := func(f func(m map[string]any)) string {
		m := goodFields()
		f(m)
		return makeToken(t, m)
	}
	bad := map[string]string{ //nolint:gosec // G101: made-up values for a format check, not credentials
		"empty":             "",
		"global api key":    strings.Repeat("ab12", 9) + "c", // 37 hex digits, like a Global API Key
		"api token":         "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-Ab",
		"pem":               "-----BEGIN ARGO TUNNEL TOKEN-----",
		"raw json":          `{"a":"0123456789abcdef0123456789abcdef"}`,
		"padded spaces":     " " + good,
		"base64url":         strings.NewReplacer("+", "-", "/", "_").Replace(good) + "-_",
		"extra key":         mut(func(m map[string]any) { m["x"] = 1 }),
		"upper-case key":    mut(func(m map[string]any) { m["A"] = m["a"]; delete(m, "a") }),
		"no secret":         mut(func(m map[string]any) { delete(m, "s") }),
		"short secret":      mut(func(m map[string]any) { m["s"] = base64.StdEncoding.EncodeToString([]byte("short")) }),
		"bad account":       mut(func(m map[string]any) { m["a"] = "ABC" }),
		"bad uuid":          mut(func(m map[string]any) { m["t"] = "not-a-uuid" }),
		"bad endpoint":      mut(func(m map[string]any) { m["e"] = "https://evil.example" }),
		"trailing data":     base64.StdEncoding.EncodeToString([]byte(`{"a":"0123456789abcdef0123456789abcdef","t":"6ff42ae2-765d-4adf-8112-31c55c1551ef","s":"a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="}{}`)),
		"too long":          strings.Repeat("A", MaxTunnelTokenLen+4),
		"secret not base64": mut(func(m map[string]any) { m["s"] = "!!!!" }),
	}
	for name, tok := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateTunnelToken(tok)
			if err == nil {
				t.Fatal("accepted")
			}
			if tok != "" && strings.Contains(err.Error(), tok) {
				t.Fatal("error repeats the value")
			}
		})
	}
}

func TestQuickShareHostname(t *testing.T) {
	for _, h := range []string{"abc-def-ghi.trycloudflare.com", "a.trycloudflare.com", "x1-2-3.trycloudflare.com"} {
		if !ValidQuickShareHostname(h) {
			t.Errorf("%q refused", h)
		}
	}
	for _, h := range []string{
		"", "trycloudflare.com", "a.b.trycloudflare.com", "evil.com", "a.trycloudflare.com.evil.com",
		"A.trycloudflare.com", "-a.trycloudflare.com", "a-.trycloudflare.com", "a.trycloudflare.com.",
		"a_b.trycloudflare.com", strings.Repeat("a", 64) + ".trycloudflare.com", "a.trycloudflare.co",
	} {
		if ValidQuickShareHostname(h) {
			t.Errorf("%q accepted", h)
		}
	}
}

// FuzzTunnelToken: no panic, and nothing is accepted that cloudflared's own
// format would not decode to a full token.
func FuzzTunnelToken(f *testing.F) {
	f.Add(makeToken(f, goodFields()))
	f.Add("1234567890abcdef1234567890abcdef12345")
	f.Add("eyJhIjoiMSJ9")
	f.Fuzz(func(t *testing.T, s string) {
		parts, err := ValidateTunnelToken(s)
		if err != nil {
			return
		}
		raw, derr := base64.StdEncoding.DecodeString(s)
		var m map[string]any
		if derr != nil || json.Unmarshal(raw, &m) != nil {
			t.Fatalf("accepted %q that does not decode", s)
		}
		if m["a"] != parts.AccountTag || m["s"] != parts.Secret || m["t"] == nil {
			t.Fatalf("parts do not match the token")
		}
	})
}
