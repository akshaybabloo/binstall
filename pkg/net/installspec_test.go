package net

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
)

// downloadConfig builds a Binaries whose download block targets this host, so
// the tests exercise the real OS/arch lookup.
func downloadConfig(t *testing.T, info models.DownloadArchInfo) models.Binaries {
	t.Helper()
	return models.Binaries{
		Name: "example",
		Download: map[string]map[string]models.DownloadArchInfo{
			runtime.GOOS: {archKeyForCurrent(t): info},
		},
	}
}

func TestResolveInstallSpec(t *testing.T) {
	yes, no := true, false

	t.Run("type on the download entry drives the install", func(t *testing.T) {
		b, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example-{{.Version}}.deb",
			Type:     "deb",
			Install:  &yes,
		}))
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeDeb, b.ResolvedType())
		assert.True(t, b.IsPackageInstall())
	})

	t.Run("type is inferred from the file name when omitted", func(t *testing.T) {
		b, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example-{{.Version}}.rpm",
		}))
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeRPM, b.ResolvedType())
		assert.True(t, b.IsPackageInstall(), "a package defaults to installing")
	})

	t.Run("install false downloads without installing", func(t *testing.T) {
		b, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example-{{.Version}}.deb",
			Install:  &no,
		}))
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeDeb, b.ResolvedType())
		assert.False(t, b.IsPackageInstall())
	})

	t.Run("an archive entry is never a package install", func(t *testing.T) {
		b, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example-{{.Version}}.tar.gz",
			Install:  &yes,
		}))
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeArchive, b.ResolvedType())
		assert.False(t, b.IsPackageInstall())
	})

	t.Run("explicit type overrides a misleading extension", func(t *testing.T) {
		b, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example-{{.Version}}.bin",
			Type:     "deb",
		}))
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeDeb, b.ResolvedType())
		assert.True(t, b.IsPackageInstall())
	})

	t.Run("no download block leaves an archive", func(t *testing.T) {
		b, err := resolveInstallSpec(models.Binaries{Name: "example"})
		require.NoError(t, err)
		assert.Equal(t, models.PackageTypeArchive, b.ResolvedType())
		assert.False(t, b.IsPackageInstall())
	})

	t.Run("another host's entry is ignored", func(t *testing.T) {
		b, err := resolveInstallSpec(models.Binaries{
			Name: "example",
			Download: map[string]map[string]models.DownloadArchInfo{
				"some-other-os": {"amd64": {FileName: "example.deb", Type: "deb"}},
			},
		})
		require.NoError(t, err)
		assert.False(t, b.IsPackageInstall())
	})

	t.Run("a bad type is reported against the config", func(t *testing.T) {
		_, err := resolveInstallSpec(downloadConfig(t, models.DownloadArchInfo{
			FileName: "example.snap",
			Type:     "snap",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "example")
	})
}

func TestResolveDownloadEntry(t *testing.T) {
	info, ok := resolveDownloadEntry(downloadConfig(t, models.DownloadArchInfo{
		FileName: "example-{{.Version}}.deb",
		Type:     "deb",
	}))
	require.True(t, ok)
	assert.Equal(t, "deb", info.Type)

	// An entry with no file name is not usable.
	_, ok = resolveDownloadEntry(downloadConfig(t, models.DownloadArchInfo{Type: "deb"}))
	assert.False(t, ok)
}

func TestResolveDownloadFileNameRendersTemplate(t *testing.T) {
	b := downloadConfig(t, models.DownloadArchInfo{FileName: "example-{{.Version}}.deb", Type: "deb"})
	assert.Equal(t, "example-v1.2.3.deb", resolveDownloadFileName(b, "v1.2.3"))
}

func TestNeedsRootForRemoval(t *testing.T) {
	// An inactive config never reaches CheckUpdates, so removal has to read
	// the download entry itself to know it is looking at a package.
	deb := downloadConfig(t, models.DownloadArchInfo{FileName: "example-{{.Version}}.deb"})
	assert.True(t, NeedsRootForRemoval(deb))
	assert.Equal(t, models.PackageTypeDeb, ResolvedInstallType(deb))

	archive := downloadConfig(t, models.DownloadArchInfo{FileName: "example-{{.Version}}.tar.gz"})
	assert.False(t, NeedsRootForRemoval(archive))
	assert.Equal(t, models.PackageTypeArchive, ResolvedInstallType(archive))

	assert.False(t, NeedsRootForRemoval(models.Binaries{Name: "example"}))
}

func TestRemoveInstalledFiles_InstallFalseLeavesInstallLocationAlone(t *testing.T) {
	// A package config never writes to InstallLocation, so removing an
	// inactive one must not delete that directory - it may belong to
	// something else entirely.
	installDir := t.TempDir()
	canary := filepath.Join(installDir, "unrelated-file")
	require.NoError(t, os.WriteFile(canary, []byte("do not delete me"), 0644))

	no := false
	b := downloadConfig(t, models.DownloadArchInfo{
		FileName: "example-{{.Version}}.deb",
		Type:     "deb",
		Install:  &no,
	})
	b.InstallLocation = installDir

	require.NoError(t, RemoveInstalledFiles(b))

	assert.FileExists(t, canary, "install: false must not delete InstallLocation")
	assert.DirExists(t, installDir)
}

func TestRemoveInstalledFiles_ArchiveStillRemovesInstallLocation(t *testing.T) {
	// The guard above must not stop an ordinary archive config from being
	// cleaned up.
	installDir := filepath.Join(t.TempDir(), "archive-install")
	require.NoError(t, os.MkdirAll(installDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(installDir, "example"), []byte("bin"), 0755))

	b := downloadConfig(t, models.DownloadArchInfo{FileName: "example-{{.Version}}.tar.gz"})
	b.InstallLocation = installDir

	require.NoError(t, RemoveInstalledFiles(b))
	assert.NoDirExists(t, installDir)
}
