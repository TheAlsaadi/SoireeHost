package redact

import (
	"net/url"
	"strings"
	"testing"
)

func TestURI(t *testing.T) {
	for in, want := range map[string]string{ //nolint:gosec // G101: URIs with fake parameters, not credentials
		"/":                         "/",
		"/a?b=1&c=2":                "/a?b=REDACTED&c=REDACTED",
		"/a?eyJhbGciOi":             "/a?REDACTED",
		"/a?x=1;y=2":                "/a?x=REDACTED;y=REDACTED",
		"/a?%zz=1":                  "/a?REDACTED",
		"/p?a=1#&token=S":           "/p?a=REDACTED&token=REDACTED",
		"/p?a=1&&b":                 "/p?a=REDACTED&&REDACTED",
		"http://h/x?code=abc&id=":   "http://h/x?code=REDACTED&id=REDACTED",
		"/q?=v":                     "/q?=REDACTED",
		"/q?name=REDACTED":          "/q?name=REDACTED",
		"/no-query#frag?with=thing": "/no-query#frag?with=REDACTED",
	} {
		if got := URI(in); got != want {
			t.Errorf("URI(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzURI (review finding GOE-14): a canary placed as any query value, or as
// a bare item, never survives, and masking is idempotent.
func FuzzURI(f *testing.F) {
	for _, s := range []string{"/a", "/a?b=", "/a?b=1&c", "/p?a=1#&t=", "/x?;;=&", "/%zz?q=", "/a?b=c=d"} {
		f.Add(s, "CANARYqq")
	}
	f.Fuzz(func(t *testing.T, prefix, canary string) {
		if len(canary) < 4 || strings.ContainsAny(canary, "?&;=#%") || strings.Contains(Masked, canary) {
			return
		}
		u := prefix + "&k=" + canary + "&" + canary
		if !strings.Contains(prefix, "?") {
			u = prefix + "?k=" + canary + "&" + canary
		}
		got := URI(u)
		_, q, _ := strings.Cut(got, "?")
		if strings.Contains(q, canary) {
			// a name may legitimately contain the canary only if the
			// canary was part of a name the input already had
			names := ""
			for g := range strings.SplitSeq(q, "&") {
				for p := range strings.SplitSeq(g, ";") {
					n, _, _ := strings.Cut(p, "=")
					names += n + "\n"
				}
			}
			if !strings.Contains(names, canary) || strings.Contains(q, "="+canary) {
				t.Fatalf("canary survived: %q -> %q", u, got)
			}
			if _, err := url.QueryUnescape(canary); err == nil && strings.Count(q, canary) > strings.Count(prefix, canary) {
				t.Fatalf("canary survived as a value or bare item: %q -> %q", u, got)
			}
		}
		if again := URI(got); again != got {
			t.Fatalf("not idempotent: %q -> %q -> %q", u, got, again)
		}
	})
}
