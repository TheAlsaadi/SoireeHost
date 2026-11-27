package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

var (
	// crsRequestRule matches the request rule files build/check-crs.ps1 accepts.
	crsRequestRule = regexp.MustCompile(`^rules/REQUEST-9[0-9]{2}-[A-Z0-9-]+\.conf$`)
	// crsDataRef matches a rule operator that loads a data file.
	crsDataRef = regexp.MustCompile(`@pm(?:FromFile|f) ([a-z0-9-]+\.data)\b`)
	// crsFileLine matches one file= line of build/crs.lock.
	crsFileLine = regexp.MustCompile(`(?m)^file=[^\r\n]*(?:\r?\n|$)`)
)

// maxCRSRuleFile bounds how much of one rule file is read from the archive.
const maxCRSRuleFile = 8 << 20

// crsFiles lists what build/crs.lock vendors from a CRS release archive: the
// LICENSE, the request rules, and the data files those rules load. Response
// rules and their data files are never listed (ADR-0008): responses are not
// inspected, and Windows Defender quarantines web-shells-php.data. Nothing is
// written to disk; only the request rules are read.
func crsFiles(archive, v string) ([]string, error) {
	f, err := os.Open(archive) // #nosec G304 G703 -- the archive this tool just downloaded
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("CRS %s archive: %w", v, err)
	}
	tr := tar.NewReader(gz)
	prefix := "coreruleset-" + v + "/"
	members := map[string]bool{}
	refs := map[string]bool{}
	var rules []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("CRS %s archive: %w", v, err)
		}
		name, ok := strings.CutPrefix(h.Name, prefix)
		if !ok || h.Typeflag != tar.TypeReg {
			continue
		}
		members[name] = true
		if !crsRequestRule.MatchString(name) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxCRSRuleFile+1))
		if err != nil {
			return nil, fmt.Errorf("CRS %s archive: %s: %w", v, name, err)
		}
		if len(b) > maxCRSRuleFile {
			return nil, fmt.Errorf("CRS %s archive: %s is larger than %d bytes", v, name, maxCRSRuleFile)
		}
		rules = append(rules, name)
		for _, m := range crsDataRef.FindAllStringSubmatch(string(b), -1) {
			refs["rules/"+m[1]] = true
		}
	}
	if !members["LICENSE"] {
		return nil, fmt.Errorf("CRS %s archive has no LICENSE", v)
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("CRS %s archive has no request rules", v)
	}
	files := rules
	for ref := range refs {
		if !members[ref] {
			return nil, fmt.Errorf("CRS %s: a request rule loads %s, which the archive does not hold", v, ref)
		}
		files = append(files, ref)
	}
	sort.Strings(files)
	return append([]string{"LICENSE"}, files...), nil
}

// setCRSFiles replaces the file= lines of build/crs.lock, which close the file.
func setCRSFiles(s string, files []string) (string, error) {
	if !crsFileLine.MatchString(s) {
		return "", errors.New("build/crs.lock has no file= lines")
	}
	s = crsFileLine.ReplaceAllString(s, "")
	if s != "" && !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	var b strings.Builder
	b.WriteString(s)
	for _, f := range files {
		b.WriteString("file=" + f + "\n")
	}
	return b.String(), nil
}
