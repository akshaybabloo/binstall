package elevate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRunner builds a Runner with every environment probe stubbed, so strategy
// resolution can be exercised without a real sudo, terminal or root.
func testRunner(uid int, available []string, tty bool) *Runner {
	present := make(map[string]bool, len(available))
	for _, name := range available {
		present[name] = true
	}
	return &Runner{
		lookPath: func(name string) (string, error) {
			if present[name] {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
		geteuid:    func() int { return uid },
		isTerminal: func() bool { return tty },
		// Stubbed so results do not depend on whether the host happens to
		// have a warm sudo timestamp.
		sudoNonInteractive: func() bool { return false },
		readPassword:       func(string) (string, error) { return "hunter2", nil },
		runSudoValidate:    func(string) error { return nil },
	}
}

func TestPrepare_AlreadyRoot(t *testing.T) {
	// No sudo and no tty: running as root still needs no escalation at all.
	r := testRunner(0, nil, false)
	require.NoError(t, r.Prepare())
	assert.Equal(t, strategyDirect, r.strategy)
	assert.Empty(t, r.password)
}

func TestPrepare_SudoPassword(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, true)
	require.NoError(t, r.Prepare())
	assert.Equal(t, strategySudoPassword, r.strategy)
	assert.Equal(t, "hunter2", r.password)
}

func TestPrepare_FallsBackToPkexecWithoutATerminal(t *testing.T) {
	// sudo exists but would need a password and there is nowhere to ask, so
	// polkit takes over - this is the cron/desktop-launcher case.
	r := testRunner(1000, []string{"sudo", "pkexec"}, false)
	require.NoError(t, r.Prepare())
	assert.Equal(t, strategyPkexec, r.strategy)
}

func TestPrepare_PkexecWhenSudoIsAbsent(t *testing.T) {
	r := testRunner(1000, []string{"pkexec"}, true)
	require.NoError(t, r.Prepare())
	assert.Equal(t, strategyPkexec, r.strategy)
}

func TestPrepare_NoEscalationAvailable(t *testing.T) {
	r := testRunner(1000, nil, false)
	err := r.Prepare()
	require.ErrorIs(t, err, ErrNoEscalation)
}

func TestPrepare_BadPassword(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, true)
	attempts := 0
	r.runSudoValidate = func(string) error {
		attempts++
		return errors.New("incorrect password")
	}

	err := r.Prepare()
	require.ErrorIs(t, err, ErrBadPassword)
	assert.Equal(t, maxPasswordAttempts, attempts)
}

func TestPrepare_RetriesThenSucceeds(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, true)
	attempts := 0
	r.runSudoValidate = func(string) error {
		attempts++
		if attempts < 2 {
			return errors.New("incorrect password")
		}
		return nil
	}

	require.NoError(t, r.Prepare())
	assert.Equal(t, strategySudoPassword, r.strategy)
	assert.Equal(t, 2, attempts)
}

func TestPrepare_IsIdempotent(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, true)
	prompts := 0
	r.readPassword = func(string) (string, error) {
		prompts++
		return "hunter2", nil
	}

	require.NoError(t, r.Prepare())
	require.NoError(t, r.Prepare())
	assert.Equal(t, 1, prompts, "a second Prepare must not re-prompt")
}

func TestAvailable(t *testing.T) {
	assert.True(t, testRunner(0, nil, false).Available())
	assert.True(t, testRunner(1000, []string{"sudo"}, true).Available())
	assert.True(t, testRunner(1000, []string{"pkexec"}, false).Available())
	assert.False(t, testRunner(1000, nil, false).Available())
	assert.False(t, testRunner(1000, []string{"sudo"}, false).Available(),
		"sudo needing a password with no terminal is not usable on its own")
}

func TestBuildCommand(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		cmd, stdin := buildCommand(strategyDirect, "", nil, "apt-get", []string{"install", "-y", "x.deb"})
		assert.Equal(t, []string{"apt-get", "install", "-y", "x.deb"}, cmd.Args)
		assert.Empty(t, stdin)
	})

	t.Run("sudo without a password", func(t *testing.T) {
		cmd, stdin := buildCommand(strategySudoNonInteractive, "", nil, "apt-get", []string{"install"})
		assert.Equal(t, []string{"sudo", "-n", "--", "apt-get", "install"}, cmd.Args)
		assert.Empty(t, stdin)
	})

	t.Run("sudo with a password writes it to stdin", func(t *testing.T) {
		cmd, stdin := buildCommand(strategySudoPassword, "hunter2", nil, "dnf", []string{"install", "-y"})
		assert.Equal(t, []string{"sudo", "-S", "-p", "", "--", "dnf", "install", "-y"}, cmd.Args)
		assert.Equal(t, "hunter2\n", stdin)
	})

	t.Run("pkexec re-applies the environment", func(t *testing.T) {
		// pkexec scrubs the environment, so DEBIAN_FRONTEND has to be
		// re-applied inside the elevated command or apt opens a dialog.
		cmd, _ := buildCommand(strategyPkexec, "", []string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", []string{"install"})
		assert.Equal(t, []string{"pkexec", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install"}, cmd.Args)
	})

	t.Run("pkexec without extra environment", func(t *testing.T) {
		cmd, _ := buildCommand(strategyPkexec, "", nil, "dnf", []string{"install"})
		assert.Equal(t, []string{"pkexec", "dnf", "install"}, cmd.Args)
	})
}

func TestRun_NoEscalationIsReportedNotHung(t *testing.T) {
	r := testRunner(1000, nil, false)
	_, err := r.Run("apt-get", "install")
	require.ErrorIs(t, err, ErrNoEscalation)
}

func TestStrategyString(t *testing.T) {
	assert.Equal(t, "direct (already root)", strategyDirect.String())
	assert.Equal(t, "pkexec", strategyPkexec.String())
	assert.Equal(t, "unresolved", strategyUnresolved.String())
}

func TestPrepare_SudoWithoutAPassword(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, true)
	r.sudoNonInteractive = func() bool { return true }

	prompts := 0
	r.readPassword = func(string) (string, error) {
		prompts++
		return "", nil
	}

	require.NoError(t, r.Prepare())
	assert.Equal(t, strategySudoNonInteractive, r.strategy)
	assert.Equal(t, 0, prompts, "a NOPASSWD rule must not trigger a prompt")
}

func TestAvailable_SudoNoPasswordWithoutATerminal(t *testing.T) {
	r := testRunner(1000, []string{"sudo"}, false)
	r.sudoNonInteractive = func() bool { return true }
	assert.True(t, r.Available())
}
