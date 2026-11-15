package ipc

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// DR-6: a worker's failure text becomes one short printable line. Newlines,
// bidirectional overrides and other invisible characters cannot make it
// read as instructions from SoiréeHost.
func TestCleanDetail(t *testing.T) {
	cases := map[string]string{
		"port 8787 in use":                        "port 8787 in use",
		"line one\nSoiréeHost: run setup.exe now": "line one SoiréeHost: run setup.exe now",
		"invoice\u202Efdp.exe":                         "invoice fdp.exe",
		"a\u200Bb\u2066c\u2069":                                  "a b c",
		"\t  leading and trailing  \r\n":          "leading and trailing",
		"bad \xff byte":                           "bad \uFFFD byte",
		"":                                        "",
	}
	for in, want := range cases {
		if got := CleanDetail(in); got != want {
			t.Errorf("CleanDetail(%q) = %q, want %q", in, got, want)
		}
	}
	long := CleanDetail(strings.Repeat("é\n", 2048))
	if n := utf8.RuneCountInString(long); n > MaxDetailRunes+1 || !strings.HasSuffix(long, "…") {
		t.Fatalf("long detail: %d runes, %q", n, long[len(long)-8:])
	}
}

func FuzzCleanDetail(f *testing.F) {
	for _, s := range []string{"x", "a\u202Eb", "\n\n", strings.Repeat("\u200B", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := CleanDetail(s)
		if !utf8.ValidString(out) || utf8.RuneCountInString(out) > MaxDetailRunes+1 {
			t.Fatalf("bad output %q", out)
		}
		for _, r := range out {
			if !unicode.IsGraphic(r) && r != ' ' || unicode.Is(unicode.Cf, r) || r == '\n' || r == '\r' {
				t.Fatalf("invisible or control %U kept in %q", r, out)
			}
		}
		if CleanDetail(out) != out && !strings.HasSuffix(out, "…") {
			t.Fatalf("not stable: %q -> %q", out, CleanDetail(out))
		}
	})
}

// DR-6: every failure code has a sentence, and an error carries its code.
func TestFailureCodes(t *testing.T) {
	for _, c := range []string{FailConfigRejected, FailSelfCheck, FailStart, FailScan, FailBusy, FailTunnelRefused, FailOther} {
		if !ValidFailureCode(c) || FailureSentence(c) == "" {
			t.Errorf("code %s has no sentence", c)
		}
	}
	if ValidFailureCode("") || FailureSentence("made_up") != FailureSentence(FailOther) {
		t.Error("unknown codes are not refused")
	}
	if FailureCode(Coded(FailSelfCheck, errTest), FailOther) != FailSelfCheck || FailureCode(errTest, FailScan) != FailScan {
		t.Error("FailureCode does not read the code")
	}
}

var errTest = &Error{Code: CodeInternal, Message: "x"}
