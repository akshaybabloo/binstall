package net

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
)

// buildFixtureDeb creates a minimal, valid .deb so the metadata-reading path is
// exercised against a real package rather than a mock. It skips when dpkg-deb
// is unavailable, which keeps the suite portable.
func buildFixtureDeb(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb is not available on this host")
	}

	root := t.TempDir()
	pkgDir := filepath.Join(root, "binstall-fixture")
	require.NoError(t, os.MkdirAll(filepath.Join(pkgDir, "DEBIAN"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(pkgDir, "usr", "bin"), 0755))

	control := "Package: binstall-fixture\n" +
		"Version: 1.2.3\n" +
		"Section: utils\n" +
		"Priority: optional\n" +
		"Architecture: all\n" +
		"Maintainer: binstall tests <test@example.com>\n" +
		"Description: fixture package for binstall tests\n"
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "DEBIAN", "control"), []byte(control), 0644))

	debPath := filepath.Join(root, "binstall-fixture_1.2.3_all.deb")
	out, err := exec.Command("dpkg-deb", "--build", pkgDir, debPath).CombinedOutput()
	require.NoError(t, err, "dpkg-deb failed: %s", out)

	return debPath
}

func TestPackageNameOf_ReadsRealDebMetadata(t *testing.T) {
	debPath := buildFixtureDeb(t)

	name, err := packageNameOf(models.Binaries{
		Name:             "fixture",
		DownloadFileName: filepath.Base(debPath),
		DownloadFilePath: debPath,
	})
	require.NoError(t, err)
	assert.Equal(t, "binstall-fixture", name, "package name comes from the control file, not the file name")
}

func TestPackageNameOf_FromInstalledBinary(t *testing.T) {
	// With nothing downloaded, the name has to come from asking the package
	// manager which package owns the binary that files names. "ls" stands in
	// for an installed binary that a real config would point at.
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not available on this host")
	}
	lsPath, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("ls is not on PATH")
	}
	owner, err := packageOwningFile(models.PackageTypeDeb, lsPath)
	if err != nil || owner == "" {
		t.Skip("ls is not owned by a deb package on this host")
	}

	name, err := packageNameOf(models.Binaries{
		Name:        "fixture",
		InstallType: "deb",
		Files:       []models.File{{FileName: "ls", CheckVersion: true}},
	})
	require.NoError(t, err)
	assert.Equal(t, owner, name)
}

func TestPackageNameOf_IgnoresFilesWithoutCheckVersion(t *testing.T) {
	// Only the checkVersion entry identifies the package, so a plain file
	// entry must not be used as the removal anchor even when it is installed.
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not available on this host")
	}
	if _, err := exec.LookPath("ls"); err != nil {
		t.Skip("ls is not on PATH")
	}

	_, err := packageNameOf(models.Binaries{
		Name:        "fixture",
		InstallType: "deb",
		Files:       []models.File{{FileName: "ls"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checkVersion: true")
}

func TestPackageNameOf_PicksTheCheckVersionEntry(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not available on this host")
	}
	lsPath, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("ls is not on PATH")
	}
	owner, err := packageOwningFile(models.PackageTypeDeb, lsPath)
	if err != nil || owner == "" {
		t.Skip("ls is not owned by a deb package on this host")
	}

	name, err := packageNameOf(models.Binaries{
		Name:        "fixture",
		InstallType: "deb",
		Files: []models.File{
			{FileName: "binstall-not-a-real-binary"},
			{FileName: "ls", CheckVersion: true},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, owner, name)
}

func TestPackageNameOf_NothingInstalledIsNotAnError(t *testing.T) {
	// The binary is not on PATH, so the package is already gone and a repeat
	// removal must stay quiet rather than fail.
	name, err := packageNameOf(models.Binaries{
		Name:        "fixture",
		InstallType: "deb",
		Files:       []models.File{{FileName: "binstall-definitely-not-on-path", CheckVersion: true}},
	})
	require.NoError(t, err)
	assert.Equal(t, "", name)
}

func TestPackageNameOf_NoFilesToGoOn(t *testing.T) {
	_, err := packageNameOf(models.Binaries{Name: "fixture", InstallType: "deb"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "files entry")
}

func TestPackageOwningFile_Deb(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not available on this host")
	}
	lsPath, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("ls is not on PATH")
	}

	owner, err := packageOwningFile(models.PackageTypeDeb, lsPath)
	if err != nil {
		t.Skip("ls is not owned by a deb package on this host")
	}
	assert.NotEmpty(t, owner)
	assert.NotContains(t, owner, ":", "any architecture qualifier must be stripped")
	assert.NotContains(t, owner, "/", "the path must not leak into the package name")
}

func TestInstalledPackageVersion_NotInstalled(t *testing.T) {
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query is not available on this host")
	}
	assert.Equal(t, "", installedPackageVersion(models.PackageTypeDeb, "binstall-definitely-not-installed"))
}

func TestRemovePackage_NotInstalledIsANoOp(t *testing.T) {
	// A config marked inactive twice in a row must not fail on the second run
	// just because the package is already gone.
	debPath := buildFixtureDeb(t)
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query is not available on this host")
	}
	if _, err := lookPath("apt-get"); err != nil {
		t.Skip("no deb package manager on this host")
	}

	err := removePackage(models.Binaries{
		Name:             "fixture",
		InstallType:      "deb",
		InstallPackage:   true,
		DownloadFileName: filepath.Base(debPath),
		DownloadFilePath: debPath,
	})
	assert.NoError(t, err, "removing a package that was never installed must be a no-op")
}

func TestResolvedTypeFromRealDebFileName(t *testing.T) {
	debPath := buildFixtureDeb(t)
	b := models.Binaries{DownloadFileName: filepath.Base(debPath), InstallPackage: true}
	assert.Equal(t, models.PackageTypeDeb, b.ResolvedType())
	assert.True(t, NeedsRoot(b))
}
