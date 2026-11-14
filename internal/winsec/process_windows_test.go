package winsec

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStartConfinedChild (S-21, S-23): a child started confined gets only the
// environment it was given, cannot start a process of its own, and its
// output reaches the parent.
func TestStartConfinedChild(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := StartConfined(ProcessSpec{
		Path: self,
		Args: []string{"-test.run=^TestConfinedChildHelper$", "-test.v"},
		Env: []string{
			"SystemRoot=" + os.Getenv("SystemRoot"),
			"SOIREEHOST_CHILD_HELPER=1",
			"SOIREEHOST_CHILD_SECRET=CANARY-ENV-ONLY",
		},
		Limits: Limits{MemoryBytes: 256 << 20, ActiveProcesses: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close() //nolint:errcheck // test cleanup

	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(p.Output)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var out []string
	timeout := time.After(60 * time.Second)
	for done := false; !done; {
		select {
		case l, ok := <-lines:
			if !ok {
				done = true
				break
			}
			out = append(out, l)
		case <-timeout:
			t.Fatalf("child did not finish; output so far:\n%s", strings.Join(out, "\n"))
		}
	}
	code, err := p.Wait()
	all := strings.Join(out, "\n")
	if err != nil || code != 0 {
		t.Fatalf("child exit %d %v:\n%s", code, err, all)
	}
	for _, want := range []string{"CHILD-ENV PATH=false", "CHILD-ENV SECRET=true", "CHILD-SPAWN refused"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in child output:\n%s", want, all)
		}
	}
}

// TestConfinedChildHelper does something only when started by
// TestStartConfinedChild.
func TestConfinedChildHelper(t *testing.T) {
	if os.Getenv("SOIREEHOST_CHILD_HELPER") != "1" {
		t.Skip("helper")
	}
	_, hasPath := os.LookupEnv("PATH")
	fmt.Printf("CHILD-ENV PATH=%v\n", hasPath)
	fmt.Printf("CHILD-ENV SECRET=%v\n", os.Getenv("SOIREEHOST_CHILD_SECRET") == "CANARY-ENV-ONLY")
	cmd := exec.CommandContext(t.Context(), filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "exit", "0") //nolint:gosec // G204: fixed System32 program
	if err := cmd.Run(); err != nil {
		fmt.Println("CHILD-SPAWN refused")
	} else {
		fmt.Println("CHILD-SPAWN allowed")
	}
}

func TestStartConfinedRefusesBadSpecs(t *testing.T) {
	if _, err := StartConfined(ProcessSpec{Path: "cmd.exe", Limits: Limits{MemoryBytes: 1, ActiveProcesses: 1}}); err == nil {
		t.Error("relative path accepted")
	}
	if _, err := StartConfined(ProcessSpec{Path: `C:\Windows\System32\cmd.exe`}); err == nil {
		t.Error("zero limits accepted")
	}
	if _, err := envBlock([]string{"=C:=C:\\"}); err == nil {
		t.Error("entry without a name accepted")
	}
	if _, err := envBlock([]string{"NOEQUALS"}); err == nil {
		t.Error("entry without = accepted")
	}
}
