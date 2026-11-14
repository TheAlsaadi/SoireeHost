package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/TheAlsaadi/SoireeHost/internal/tunnel"
)

// Cloudflared is the unpacked cloudflared.exe (S-23).
func (l Layout) Cloudflared() string { return filepath.Join(l.ProgramDir, tunnel.ExeName) }

// installCloudflared writes the cloudflared compiled into this build next to
// the installed program, as a new file that takes the program folder's
// permissions (administrators write, everyone else reads and executes). The
// bytes are checked against the pin before anything is written, and the
// written file is read back and checked again (ADR-0002, ADR-0007). A build
// without cloudflared installs without it, unless it is a release build;
// the tunnel then reports Repair needed.
func installCloudflared(l Layout) (written bool, err error) {
	b, err := tunnel.Embedded()
	if errors.Is(err, tunnel.ErrNotEmbedded) && !requireCloudflared {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	dst := l.Cloudflared()
	tmp := dst + ".new"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755) // #nosec G302 G304 -- program file under Program Files
	if err != nil {
		return false, err
	}
	if _, err := out.Write(b); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	from, _ := windows.UTF16PtrFromString(tmp)
	to, _ := windows.UTF16PtrFromString(dst)
	// A cloudflared of the install being replaced ends when the stopped
	// launcher's job handle closes, a moment after its service stops; until
	// then its image is mapped and cannot be replaced.
	deadline := time.Now().Add(30 * time.Second)
	for {
		err = windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
		if err == nil {
			break
		}
		if (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION)) || time.Now().After(deadline) {
			_ = os.Remove(tmp)
			return false, err
		}
		time.Sleep(500 * time.Millisecond)
	}
	back, err := os.ReadFile(dst) // #nosec G304 -- the file just written under Program Files
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(back)
	if hex.EncodeToString(sum[:]) != tunnel.CloudflaredSHA256 {
		_ = os.Remove(dst)
		return false, errors.New("the unpacked cloudflared.exe does not match its pinned hash; it was removed")
	}
	return true, nil
}

// Firewall rule names (S-02). Setup creates only these two inbound block
// rules and never an allow rule.
const (
	firewallRuleSelf        = "SoireeHost block inbound soireehost.exe"
	firewallRuleCloudflared = "SoireeHost block inbound cloudflared.exe"
)

// firewallRules lists each rule with the program it blocks.
func (l Layout) firewallRules() [][2]string {
	return [][2]string{{firewallRuleSelf, l.Exe()}, {firewallRuleCloudflared, l.Cloudflared()}}
}

// netshArgs are the arguments, after the program name, of the netsh command
// lines setup runs. Everything is fixed except the installed program path,
// which is quoted and cannot contain a quote (Windows paths cannot).
func netshAdd(name, program string) string {
	return fmt.Sprintf(`advfirewall firewall add rule name="%s" dir=in action=block program="%s" enable=yes profile=any`, name, program)
}

func netshDelete(name string) string {
	return fmt.Sprintf(`advfirewall firewall delete rule name="%s"`, name)
}

// netsh runs %SystemRoot%\System32\netsh.exe with the given arguments. The
// command line is passed as written, because netsh reads quotes inside an
// argument (name="...") that Go's own quoting would change.
func netsh(args string) error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	exe := filepath.Join(sys, "netsh.exe")
	if strings.ContainsAny(args, "\r\n") {
		return errors.New("netsh: bad arguments")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe) // #nosec G204 -- System32 netsh with fixed arguments built above
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: `"` + exe + `" ` + args}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("netsh %s: %w: %s", args, err, strings.TrimSpace(out.String()))
	}
	return nil
}

// addFirewallRules replaces both block rules (S-02). In Windows Firewall a
// block rule wins over any allow rule, so an "allow" answered later by
// mistake changes nothing.
func addFirewallRules(l Layout) error {
	removeFirewallRules(l)
	for _, r := range l.firewallRules() {
		if strings.Contains(r[1], `"`) {
			return errors.New("the program path contains a quote")
		}
		if err := netsh(netshAdd(r[0], r[1])); err != nil {
			return fmt.Errorf("adding firewall rule: %w", err)
		}
	}
	return nil
}

// removeFirewallRules deletes both rules; a rule that is not there is not an
// error.
func removeFirewallRules(l Layout) {
	for _, r := range l.firewallRules() {
		_ = netsh(netshDelete(r[0]))
	}
}
