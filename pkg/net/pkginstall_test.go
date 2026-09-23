package net

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
)

// stubLookPath replaces the PATH lookup for the duration of a test so package
// manager selection can be exercised on any host.
func stubLookPath(t *testing.T, available ...string) {
	t.Helper()
	present := make(map[string]bool, len(available))
	for _, name := range available {
		present[name] = true
	}
	original := lookPath
	lookPath = func(name string) (string, error) {
		if present[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { lookPath = original })
}

func TestResolvePackageManager(t *testing.T) {
	t.Run("prefers apt-get over dpkg for deb", func(t *testing.T) {
		stubLookPath(t, "dpkg", "apt-get")
		m, err := resolvePackageManager(models.PackageTypeDeb)
		require.NoError(t, err)
		assert.Equal(t, "apt-get", m.name)
	})

	t.Run("falls back to dpkg when apt-get is missing", func(t *testing.T) {
		stubLookPath(t, "dpkg")
		m, err := resolvePackageManager(models.PackageTypeDeb)
		require.NoError(t, err)
		assert.Equal(t, "dpkg", m.name)
	})

	t.Run("prefers dnf over rpm", func(t *testing.T) {
		stubLookPath(t, "rpm", "yum", "dnf")
		m, err := resolvePackageManager(models.PackageTypeRPM)
		require.NoError(t, err)
		assert.Equal(t, "dnf", m.name)
	})

	t.Run("picks zypper on suse", func(t *testing.T) {
		stubLookPath(t, "zypper", "rpm")
		m, err := resolvePackageManager(models.PackageTypeRPM)
		require.NoError(t, err)
		assert.Equal(t, "zypper", m.name)
	})

	t.Run("reports what it looked for when nothing is available", func(t *testing.T) {
		stubLookPath(t)
		_, err := resolvePackageManager(models.PackageTypeDeb)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deb")
		assert.Contains(t, err.Error(), "apt-get")
		assert.Contains(t, err.Error(), "dpkg")
	})

	t.Run("archive has no package manager", func(t *testing.T) {
		stubLookPath(t, "apt-get", "dnf")
		_, err := resolvePackageManager(models.PackageTypeArchive)
		require.Error(t, err)
	})
}

func TestInstallArgs(t *testing.T) {
	stubLookPath(t, "apt-get")
	m, err := resolvePackageManager(models.PackageTypeDeb)
	require.NoError(t, err)
	assert.Equal(t, []string{"install", "-y", "--allow-downgrades", "/tmp/x.deb"}, m.installArgs("/tmp/x.deb"))
	assert.Equal(t, []string{"remove", "-y", "slack-desktop"}, m.removeArgs("slack-desktop"))
	assert.Contains(t, m.env, "DEBIAN_FRONTEND=noninteractive")
}

func TestRepairFor(t *testing.T) {
	t.Run("apt-get has no repair step", func(t *testing.T) {
		stubLookPath(t, "apt-get")
		m, err := resolvePackageManager(models.PackageTypeDeb)
		require.NoError(t, err)
		_, _, ok := repairFor(m)
		assert.False(t, ok)
	})

	t.Run("dpkg repairs with apt-get when it exists", func(t *testing.T) {
		stubLookPath(t, "dpkg")
		m, err := resolvePackageManager(models.PackageTypeDeb)
		require.NoError(t, err)

		// repair consults the real PATH, so the expectation depends on the host.
		name, args, ok := repairFor(m)
		if _, err := exec.LookPath("apt-get"); err == nil {
			require.True(t, ok)
			assert.Equal(t, "apt-get", name)
			assert.Equal(t, []string{"-f", "install", "-y"}, args)
		} else {
			assert.False(t, ok)
		}
	})
}

func TestPackageManagerName(t *testing.T) {
	stubLookPath(t, "apt-get")

	deb := models.Binaries{InstallType: "deb", InstallPackage: true}
	assert.Equal(t, "apt-get", PackageManagerName(deb))

	inferred := models.Binaries{DownloadFileName: "x_1.0_amd64.deb", InstallPackage: true}
	assert.Equal(t, "apt-get", PackageManagerName(inferred))

	assert.Equal(t, "", PackageManagerName(models.Binaries{InstallType: "archive"}))
	assert.Equal(t, "", PackageManagerName(models.Binaries{InstallType: "deb"}), "install: false is not a package install")
	assert.Equal(t, "", PackageManagerName(models.Binaries{InstallType: "rpm", InstallPackage: true}), "no rpm tooling available")
}

func TestNeedsRoot(t *testing.T) {
	assert.True(t, NeedsRoot(models.Binaries{InstallType: "deb", InstallPackage: true}))
	assert.True(t, NeedsRoot(models.Binaries{InstallType: "rpm", InstallPackage: true}))
	assert.False(t, NeedsRoot(models.Binaries{InstallType: "deb"}))
	assert.False(t, NeedsRoot(models.Binaries{InstallType: "archive"}))
	assert.False(t, NeedsRoot(models.Binaries{DownloadFileName: "x.tar.gz"}))
}

func TestPackageNameOf(t *testing.T) {
	t.Run("explains what is missing with nothing to go on", func(t *testing.T) {
		_, err := packageNameOf(models.Binaries{Name: "slack", InstallType: "deb"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deleteIfNotActive")
		assert.Contains(t, err.Error(), "checkVersion: true")
	})

	t.Run("archive is not a package", func(t *testing.T) {
		_, err := packageNameOf(models.Binaries{Name: "bat", DownloadFilePath: "/tmp/bat.tar.gz"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a package install")
	})
}

func TestInstalledPackageVersion_UnknownType(t *testing.T) {
	assert.Equal(t, "", installedPackageVersion(models.PackageTypeArchive, "bat"))
}

func TestInstallPackage_NoManager(t *testing.T) {
	stubLookPath(t)
	err := installPackage(models.Binaries{Name: "slack", InstallType: "deb", InstallPackage: true, DownloadFilePath: "/tmp/slack.deb"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no package manager found")
}
