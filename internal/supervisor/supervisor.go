package supervisor

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Supervisor manages mihomo as a subprocess of fnos-mihomo-dashboard.
// It lets the dashboard offer ON/OFF / restart toggles without going
// back to the fnOS app-center.
type Supervisor struct {
	BinPath   string
	ConfigDir string
	LogPath   string

	mu  sync.Mutex
	cmd *exec.Cmd
}

func New(bin, configDir, logPath string) *Supervisor {
	return &Supervisor{BinPath: bin, ConfigDir: configDir, LogPath: logPath}
}

// Running reports whether the supervised mihomo process is currently alive.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runningLocked()
}

func (s *Supervisor) runningLocked() bool {
	if s.cmd == nil || s.cmd.Process == nil {
		return false
	}
	return s.cmd.Process.Signal(syscall.Signal(0)) == nil
}

// PID returns the current mihomo PID (0 if not running).
func (s *Supervisor) PID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.runningLocked() {
		return 0
	}
	return s.cmd.Process.Pid
}

// Start spawns mihomo with `-d <configDir>` and reaps it in a goroutine.
// Returns an error if mihomo is already running.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runningLocked() {
		return errors.New("mihomo already running")
	}
	f, err := os.OpenFile(s.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	cmd := exec.Command(s.BinPath, "-d", s.ConfigDir)
	cmd.Stdout = f
	cmd.Stderr = f
	if err := cmd.Start(); err != nil {
		_ = f.Close()
		return err
	}
	s.cmd = cmd
	// Reap on its own goroutine so the OS doesn't leak zombies.
	go func() {
		_ = cmd.Wait()
		_ = f.Close()
	}()
	return nil
}

// Stop sends SIGTERM, waits up to 8s, then SIGKILL if still alive.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if !s.runningLocked() {
		s.mu.Unlock()
		return errors.New("mihomo not running")
	}
	proc := s.cmd.Process
	s.mu.Unlock()
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if proc.Signal(syscall.Signal(0)) != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return proc.Kill()
}

// Restart = Stop + Start. Stop errors are downgraded to no-op when not running.
func (s *Supervisor) Restart() error {
	if s.Running() {
		if err := s.Stop(); err != nil {
			return err
		}
		// brief grace period before re-binding port
		time.Sleep(300 * time.Millisecond)
	}
	return s.Start()
}
