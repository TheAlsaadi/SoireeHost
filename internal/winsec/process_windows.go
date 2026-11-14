package winsec

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessSpec describes a child process to start confined (S-21: the tunnel
// launcher applies the worker limits to cloudflared).
type ProcessSpec struct {
	// Path is the absolute path of the program. It is passed as the
	// application name, so Windows never searches for it.
	Path string
	// Args are the arguments after the program name. They go on the command
	// line, which any local user can read: never put a secret here.
	Args []string
	// Env is the child's whole environment as KEY=VALUE. Nothing is
	// inherited from this process.
	Env []string
	// Dir is the working folder; empty means this process's.
	Dir string
	// Limits are the child's job limits. Its own job also forbids it any
	// child process of its own.
	Limits Limits
}

// ConfinedProcess is a child started by StartConfined.
type ConfinedProcess struct {
	// Pid is the child's process id.
	Pid uint32
	// Output carries the child's stdout and stderr, merged.
	Output *os.File

	proc windows.Handle
	job  windows.Handle
}

// processCreationChildProcessRestricted is PROCESS_CREATION_CHILD_PROCESS_RESTRICTED.
const processCreationChildProcessRestricted = 0x01

// procThreadAttributeChildProcessPolicy is PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
// (ProcThreadAttributeValue(14, FALSE, TRUE, FALSE)).
const procThreadAttributeChildProcessPolicy = 0x0002000E

// StartConfined starts a program with nothing but the given environment, its
// stdin on NUL, its stdout and stderr on a pipe this process reads, and only
// those handles inherited. The child is created suspended, put in a
// kill-on-close job of its own with spec.Limits (nested in this process's
// job), forbidden from creating processes by the child-process policy, and
// only then resumed, so it never runs a single instruction outside its
// limits. If any step fails the child is killed and an error returned.
//
// UI restrictions: Windows refuses to add a process to a nested job that
// sets them ("The request is not supported"), and a job's UI restrictions
// already apply to every process in the jobs nested inside it. So the
// child's own job sets them only when this process is in no job; the tunnel
// launcher is always in its own confined job (found in the CI isolation
// job, pull request 7).
func StartConfined(spec ProcessSpec) (*ConfinedProcess, error) {
	if spec.Limits.ActiveProcesses == 0 || spec.Limits.MemoryBytes == 0 {
		return nil, errors.New("start confined: limits must be set")
	}
	if !strings.Contains(spec.Path, `\`) {
		return nil, errors.New("start confined: the program path must be absolute")
	}
	inherit := &windows.SecurityAttributes{InheritHandle: 1}
	inherit.Length = uint32(unsafe.Sizeof(*inherit))

	var outR, outW windows.Handle
	if err := windows.CreatePipe(&outR, &outW, inherit, 0); err != nil {
		return nil, fmt.Errorf("creating the output pipe: %w", err)
	}
	// only the write end goes to the child
	if err := windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		_ = windows.CloseHandle(outR)
		_ = windows.CloseHandle(outW)
		return nil, err
	}
	output := os.NewFile(uintptr(outR), "child output")
	defer windows.CloseHandle(outW) //nolint:errcheck // the child holds its own copy

	nulName, _ := windows.UTF16PtrFromString("NUL")
	nul, err := windows.CreateFile(nulName, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		inherit, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("opening NUL: %w", err)
	}
	defer windows.CloseHandle(nul) //nolint:errcheck // the child holds its own copy

	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	defer attrs.Delete()
	handles := []windows.Handle{outW, nul}
	// #nosec G103 -- passing a handle array and its size to a Windows API, as its documentation requires
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("limiting inherited handles: %w", err)
	}
	policy := uint32(processCreationChildProcessRestricted)
	// #nosec G103 -- passing a DWORD and its size to a Windows API, as its documentation requires
	if err := attrs.Update(procThreadAttributeChildProcessPolicy, unsafe.Pointer(&policy), unsafe.Sizeof(policy)); err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("forbidding child processes: %w", err)
	}

	si := new(windows.StartupInfoEx)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = nul, outW, outW
	si.ProcThreadAttributeList = attrs.List()

	app, err := windows.UTF16PtrFromString(spec.Path)
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	cmd, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{spec.Path}, spec.Args...)))
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	env, err := envBlock(spec.Env)
	if err != nil {
		_ = output.Close()
		return nil, err
	}
	var dir *uint16
	if spec.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(spec.Dir); err != nil {
			_ = output.Close()
			return nil, err
		}
	}
	// DETACHED_PROCESS, not CREATE_NO_WINDOW: a hidden console still needs a
	// conhost.exe started for the child, which the child-process policy
	// refuses, and the child then dies in DLL start-up (0xC0000142). With no
	// console at all, its output goes straight to the pipe.
	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT |
		windows.CREATE_UNICODE_ENVIRONMENT | windows.DETACHED_PROCESS)
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(app, cmd, nil, nil, true, flags, &env[0], dir, &si.StartupInfo, &pi); err != nil {
		_ = output.Close()
		return nil, fmt.Errorf("starting %s: %w", spec.Path, err)
	}
	fail := func(err error) (*ConfinedProcess, error) {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Thread)
		_ = windows.CloseHandle(pi.Process)
		_ = output.Close()
		return nil, err
	}
	job, err := newJob(spec.Limits, !inAnyJob())
	if err != nil {
		return fail(err)
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.CloseHandle(job)
		return fail(fmt.Errorf("putting the child in its job: %w", err))
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.CloseHandle(job)
		return fail(fmt.Errorf("resuming the child: %w", err))
	}
	_ = windows.CloseHandle(pi.Thread)
	return &ConfinedProcess{Pid: pi.ProcessId, Output: output, proc: pi.Process, job: job}, nil
}

// envBlock builds a CREATE_UNICODE_ENVIRONMENT block: KEY=VALUE strings,
// sorted case-insensitively as Windows expects, each ended by a NUL, and a
// final NUL.
func envBlock(env []string) ([]uint16, error) {
	sorted := slices.Clone(env)
	slices.SortFunc(sorted, func(a, b string) int { return strings.Compare(strings.ToUpper(a), strings.ToUpper(b)) })
	var block []uint16
	for _, kv := range sorted {
		if !strings.Contains(kv, "=") || strings.HasPrefix(kv, "=") || strings.ContainsRune(kv, 0) {
			return nil, errors.New("start confined: malformed environment entry")
		}
		u, err := windows.UTF16FromString(kv)
		if err != nil {
			return nil, err
		}
		block = append(block, u...) // ends with its NUL
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}

// Wait waits for the child to end and returns its exit code.
func (p *ConfinedProcess) Wait() (uint32, error) {
	if _, err := windows.WaitForSingleObject(p.proc, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(p.proc, &code); err != nil {
		return 0, err
	}
	return code, nil
}

// Kill ends the child (and anything in its job).
func (p *ConfinedProcess) Kill() error { return windows.TerminateJobObject(p.job, 1) }

// Close kills the child if it is still running and releases its handles.
func (p *ConfinedProcess) Close() error {
	_ = windows.TerminateJobObject(p.job, 1)
	err := errors.Join(windows.CloseHandle(p.job), windows.CloseHandle(p.proc))
	_ = p.Output.Close()
	return err
}
