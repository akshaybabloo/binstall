// Package elevate runs commands as root, acquiring privileges on demand.
//
// Privileges are resolved once per process and reused, so a run that installs
// several packages asks for a password at most once. The resolution order is:
//
//  1. Already running as root - the command is executed directly.
//  2. "sudo -n" works (NOPASSWD rule or a warm sudo timestamp).
//  3. sudo is available and stdin is a terminal - the password is read once
//     without echo and piped to "sudo -S".
//  4. pkexec is available - polkit handles the prompt, which is what makes
//     this work from a desktop session with no controlling terminal.
//
// If none apply, Prepare returns ErrNoEscalation so the caller can report a
// useful message instead of hanging on an invisible prompt.
package elevate

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/term"
)

// ErrNoEscalation is returned when no usable way to become root was found.
var ErrNoEscalation = errors.New("cannot acquire root privileges: not running as root, sudo needs a password but there is no terminal to ask on, and pkexec is unavailable")

// ErrBadPassword is returned when sudo rejects the password too many times.
var ErrBadPassword = errors.New("sudo authentication failed")

// maxPasswordAttempts caps the retries so a wrong password does not loop forever.
const maxPasswordAttempts = 3

type strategy int

const (
	strategyUnresolved strategy = iota
	strategyDirect
	strategySudoNonInteractive
	strategySudoPassword
	strategyPkexec
)

func (s strategy) String() string {
	switch s {
	case strategyDirect:
		return "direct (already root)"
	case strategySudoNonInteractive:
		return "sudo (no password required)"
	case strategySudoPassword:
		return "sudo (password)"
	case strategyPkexec:
		return "pkexec"
	default:
		return "unresolved"
	}
}

// Runner executes commands as root. The zero value is ready to use and is safe
// for concurrent use; the first caller resolves the strategy and any later
// caller reuses it.
type Runner struct {
	mu       sync.Mutex
	strategy strategy
	password string

	// lookPath and geteuid are swapped out in tests.
	lookPath func(string) (string, error)
	geteuid  func() int
	// isTerminal reports whether a password can be prompted for.
	isTerminal func() bool
	// sudoNonInteractive reports whether sudo runs without a password.
	sudoNonInteractive func() bool
	// readPassword reads a password without echoing it.
	readPassword func(prompt string) (string, error)
	// runSudoValidate validates a password with "sudo -S -v".
	runSudoValidate func(password string) error
}

// New returns a Runner backed by the real process environment.
func New() *Runner {
	return &Runner{
		lookPath:           exec.LookPath,
		geteuid:            os.Geteuid,
		isTerminal:         func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		sudoNonInteractive: sudoNonInteractiveWorks,
		readPassword:       readPasswordFromTerminal,
		runSudoValidate:    sudoValidate,
	}
}

// Available reports whether a root command could plausibly be run, without
// prompting for anything. It is a cheap pre-flight check for callers that want
// to fail early rather than half-way through an install.
func (r *Runner) Available() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.strategy != strategyUnresolved {
		return true
	}
	if r.geteuid() == 0 {
		return true
	}
	if _, err := r.lookPath("sudo"); err == nil && (r.sudoNonInteractive() || r.isTerminal()) {
		return true
	}
	_, err := r.lookPath("pkexec")
	return err == nil
}

// Prepare resolves how to become root, prompting for a password if that is the
// only option. Callers should invoke it at a point where a prompt is
// acceptable - with any spinner stopped and before fanning out to workers - so
// that concurrent Run calls never contend for the terminal.
func (r *Runner) Prepare() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prepareLocked()
}

func (r *Runner) prepareLocked() error {
	if r.strategy != strategyUnresolved {
		return nil
	}

	if r.geteuid() == 0 {
		r.strategy = strategyDirect
		logrus.Debug("Privilege escalation: already running as root")
		return nil
	}

	_, sudoErr := r.lookPath("sudo")
	if sudoErr == nil {
		if r.sudoNonInteractive() {
			r.strategy = strategySudoNonInteractive
			logrus.Debug("Privilege escalation: sudo without a password")
			return nil
		}
		if r.isTerminal() {
			if err := r.promptForPassword(); err != nil {
				return err
			}
			r.strategy = strategySudoPassword
			logrus.Debug("Privilege escalation: sudo with a password")
			return nil
		}
	}

	if _, err := r.lookPath("pkexec"); err == nil {
		r.strategy = strategyPkexec
		logrus.Debug("Privilege escalation: pkexec")
		return nil
	}

	return ErrNoEscalation
}

// promptForPassword asks for the sudo password and validates it before the
// caller commits to running anything, so a typo surfaces immediately rather
// than as a confusing package manager failure.
func (r *Runner) promptForPassword() error {
	for attempt := 1; attempt <= maxPasswordAttempts; attempt++ {
		prompt := "[binstall] password for sudo (needed to install packages): "
		if attempt > 1 {
			prompt = "[binstall] sorry, try again: "
		}
		password, err := r.readPassword(prompt)
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if err := r.runSudoValidate(password); err == nil {
			r.password = password
			return nil
		}
	}
	return ErrBadPassword
}

// Run executes name with args as root and returns its combined output.
func (r *Runner) Run(name string, args ...string) ([]byte, error) {
	return r.RunWithEnv(nil, name, args...)
}

// RunWithEnv is Run with extra "KEY=value" entries added to the environment of
// the elevated command.
func (r *Runner) RunWithEnv(extraEnv []string, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	if err := r.prepareLocked(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	strat, password := r.strategy, r.password
	r.mu.Unlock()

	cmd, stdin := buildCommand(strat, password, extraEnv, name, args)
	cmd.Env = append(os.Environ(), extraEnv...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	logrus.Debugf("Running as root via %s: %s %s", strat, name, strings.Join(args, " "))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s failed: %w", name, strings.Join(args, " "), err)
	}
	return out, nil
}

// buildCommand wraps the target command for the resolved strategy and returns
// anything that must be written to its stdin.
func buildCommand(strat strategy, password string, extraEnv []string, name string, args []string) (*exec.Cmd, string) {
	switch strat {
	case strategySudoNonInteractive:
		return exec.Command("sudo", append([]string{"-n", "--"}, append([]string{name}, args...)...)...), ""
	case strategySudoPassword:
		// -S reads the password from stdin; -p "" suppresses sudo's own prompt
		// since the password was already collected by promptForPassword.
		return exec.Command("sudo", append([]string{"-S", "-p", "", "--"}, append([]string{name}, args...)...)...), password + "\n"
	case strategyPkexec:
		// pkexec scrubs the environment, so anything the command needs has to
		// be re-applied inside the elevated shell via env(1).
		pkArgs := []string{}
		if len(extraEnv) > 0 {
			pkArgs = append(pkArgs, "env")
			pkArgs = append(pkArgs, extraEnv...)
		}
		pkArgs = append(pkArgs, name)
		pkArgs = append(pkArgs, args...)
		return exec.Command("pkexec", pkArgs...), ""
	default:
		return exec.Command(name, args...), ""
	}
}

// sudoNonInteractiveWorks reports whether sudo can run without a password,
// either through a NOPASSWD rule or an unexpired timestamp.
func sudoNonInteractiveWorks() bool {
	cmd := exec.Command("sudo", "-n", "true")
	cmd.Stdin = bytes.NewReader(nil)
	return cmd.Run() == nil
}

// sudoValidate refreshes the sudo timestamp with the given password, which both
// checks the password and warms the cache for the commands that follow.
func sudoValidate(password string) error {
	cmd := exec.Command("sudo", "-S", "-p", "", "-v")
	cmd.Stdin = strings.NewReader(password + "\n")
	return cmd.Run()
}

// readPasswordFromTerminal reads a password from stdin with echo disabled.
func readPasswordFromTerminal(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(password), nil
}
