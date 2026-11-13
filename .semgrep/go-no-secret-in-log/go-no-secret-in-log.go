// Test cases for the go-no-secret-in-log rule (S-40). Not compiled: the go
// tool skips directories whose name starts with a dot.
package leaks

import (
	"errors"
	"fmt"
	"log"
	"os"

	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/TheAlsaadi/SoireeHost/internal/audit"
	"github.com/TheAlsaadi/SoireeHost/internal/ipc"
	"github.com/TheAlsaadi/SoireeHost/internal/secrets"
)

type Supervisor struct {
	secrets *secrets.Store
	audit   *audit.Log
	logger  *zap.Logger
}

func (s *Supervisor) record(actor, action string, detail map[string]string) {}

func fromStore(st *secrets.Store, logger *zap.Logger, sugar *zap.SugaredLogger) error {
	tok, err := st.Get(secrets.TunnelToken)
	if err != nil {
		// ok: go-no-secret-in-log
		return fmt.Errorf("reading the token: %w", err)
	}
	// ruleid: go-no-secret-in-log
	fmt.Println("token", string(tok))
	// ruleid: go-no-secret-in-log
	fmt.Fprintf(os.Stderr, "token %s\n", tok)
	// ruleid: go-no-secret-in-log
	log.Printf("token %s", tok)
	// ruleid: go-no-secret-in-log
	logger.Info("loaded", zap.ByteString("token", tok))
	// ruleid: go-no-secret-in-log
	sugar.Infof("loaded %s", tok)
	// ok: go-no-secret-in-log
	logger.Info("loaded", zap.Int("length", len(tok)))
	// ok: go-no-secret-in-log
	fmt.Println("token is set:", len(tok) > 0)
	// ok: go-no-secret-in-log
	fmt.Println("token is set:", tok != nil)
	if len(tok) > 0 {
		// ruleid: go-no-secret-in-log
		return errors.New("bad token " + string(tok))
	}
	if err := st.Set(secrets.TunnelToken, tok); err != nil {
		// ok: go-no-secret-in-log
		log.Println("storing failed:", err)
	}
	return nil
}

func (s *Supervisor) fromField() {
	tok, err := s.secrets.Get(secrets.TunnelToken)
	if err != nil {
		// ok: go-no-secret-in-log
		s.logger.Error("reading the token failed", zap.Error(err))
		return
	}
	msg := "token=" + string(tok)
	// ruleid: go-no-secret-in-log
	s.logger.Debug(msg)
	// ruleid: go-no-secret-in-log
	s.audit.Append("system", "secret.read", map[string]string{"value": string(tok)})
	// ok: go-no-secret-in-log
	s.audit.Append("system", "secret.read", map[string]string{"name": secrets.TunnelToken})
	// ok: go-no-secret-in-log
	_ = s.sendToWorker(ipc.WorkerMsg{Type: "load", Token: string(tok)})
}

func reassigned(st *secrets.Store) {
	var tok []byte
	var err error
	tok, err = st.Get(secrets.TunnelToken)
	// ok: go-no-secret-in-log
	log.Println("get failed:", err)
	// ruleid: go-no-secret-in-log
	log.Println("token:", tok)
}

func declared(st *secrets.Store) {
	var tok, err = st.Get(secrets.TunnelToken)
	// ok: go-no-secret-in-log
	log.Println("get failed:", err)
	// ruleid: go-no-secret-in-log
	log.Fatalf("token: %s", tok)
}

func storeIt(name string, value []byte) error { return nil }

func (s *Supervisor) sendToWorker(m ipc.WorkerMsg) error { return nil }

func (s *Supervisor) secretSet(p *ipc.SecretSetParams) error {
	if err := s.secrets.Set(p.Name, []byte(p.Value)); err != nil {
		// ok: go-no-secret-in-log
		return fmt.Errorf("the token could not be stored: %v", err)
	}
	if err := storeIt(p.Name, []byte(p.Value)); err != nil {
		// ruleid: go-no-secret-in-log
		return fmt.Errorf("the token could not be stored: %v", err)
	}
	// ok: go-no-secret-in-log
	s.record("user", "secret.set", map[string]string{"name": p.Name})
	// ruleid: go-no-secret-in-log
	s.record("user", "secret.set", map[string]string{"value": p.Value})
	if p.Value == "" {
		// ok: go-no-secret-in-log
		return fmt.Errorf("secret %q is empty", p.Name)
	}
	// ruleid: go-no-secret-in-log
	return fmt.Errorf("could not store %q", p.Value)
}

func secretByValue(p ipc.SecretSetParams) string {
	v := p.Value
	// ruleid: go-no-secret-in-log
	return fmt.Sprintf("value=%s", v)
}

func workerMessage(m ipc.WorkerMsg, elog *eventlog.Log) {
	for i := 0; i < 1; i++ {
		// ruleid: go-no-secret-in-log
		_ = elog.Error(1, "token "+m.Token)
	}
	// ok: go-no-secret-in-log
	_ = elog.Info(1, "message type "+m.Type)
	// ok: go-no-secret-in-log
	log.Printf("worker message %v", m)
}

func workerPointer(m *ipc.WorkerMsg, logger *log.Logger) {
	// ruleid: go-no-secret-in-log
	logger.Println(m.Token)
	// ok: go-no-secret-in-log
	logger.Println(m.Role)
}

func unrelatedStore(cfg interface{ Get(rev uint64) (string, error) }) {
	rec, _ := cfg.Get(3)
	// ok: go-no-secret-in-log
	fmt.Println(rec)
}
