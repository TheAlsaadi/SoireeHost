package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeCRSArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "crs.tar.gz")
	f, err := os.Create(p) //nolint:gosec // G304: path is under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []interface{ Close() error }{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestCRSFilesListsRequestRulesAndTheirData(t *testing.T) {
	p := "coreruleset-4.31.0/"
	archive := writeCRSArchive(t, map[string]string{
		p + "LICENSE": "license",
		p + "rules/REQUEST-913-SCANNER-DETECTION.conf":                  `SecRule X "@pmFromFile scanners.data" "id:1"` + "\n# see old.data\n",
		p + "rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf":             `SecRule X "@pmf unix-shell.data" "id:2"`,
		p + "rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example": "",
		p + "rules/RESPONSE-955-WEB-SHELLS.conf":                        `SecRule X "@pmFromFile web-shells-php.data" "id:3"`,
		p + "rules/scanners.data":                                       "a",
		p + "rules/unix-shell.data":                                     "b",
		p + "rules/web-shells-php.data":                                 "c",
		p + "rules/unused.data":                                         "d",
		"other/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf":             "",
	})
	got, err := crsFiles(archive, "4.31.0")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"LICENSE",
		"rules/REQUEST-913-SCANNER-DETECTION.conf",
		"rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf",
		"rules/scanners.data",
		"rules/unix-shell.data",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("crsFiles = %q, want %q", got, want)
	}
}

func TestCRSFilesRefusesMissingData(t *testing.T) {
	p := "coreruleset-4.31.0/"
	archive := writeCRSArchive(t, map[string]string{
		p + "LICENSE": "license",
		p + "rules/REQUEST-913-SCANNER-DETECTION.conf": `SecRule X "@pmFromFile scanners.data" "id:1"`,
	})
	if _, err := crsFiles(archive, "4.31.0"); err == nil {
		t.Fatal("accepted a rule that loads a data file the archive lacks")
	}
	if _, err := crsFiles(writeCRSArchive(t, map[string]string{p + "LICENSE": "x"}), "4.31.0"); err == nil {
		t.Fatal("accepted an archive without request rules")
	}
}

func TestSetCRSFiles(t *testing.T) {
	in := "version=1\n# Request rules only\nfile=LICENSE\nfile=rules/old.data\n"
	got, err := setCRSFiles(in, []string{"LICENSE", "rules/new.data"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "version=1\n# Request rules only\nfile=LICENSE\nfile=rules/new.data\n"; got != want {
		t.Fatalf("setCRSFiles = %q, want %q", got, want)
	}
	if _, err := setCRSFiles("version=1\n", []string{"LICENSE"}); err == nil {
		t.Fatal("accepted a lock without file= lines")
	}
}
