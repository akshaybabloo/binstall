package net

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/utils"
)

// archKeyForCurrent returns an arch key that NormalizeArch maps to runtime.GOARCH.
// Used so tests work regardless of host arch.
func archKeyForCurrent(t *testing.T) string {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i386"
	default:
		return runtime.GOARCH
	}
}

func TestResolveDownloadFileName(t *testing.T) {
	t.Run("nil_download_map", func(t *testing.T) {
		b := models.Binaries{}
		assert.Equal(t, "", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("os_not_in_map", func(t *testing.T) {
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				"some-other-os": {"x86_64": {FileName: "x"}},
			},
		}
		assert.Equal(t, "", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("arch_not_in_map", func(t *testing.T) {
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {"some-other-arch": {FileName: "x"}},
			},
		}
		assert.Equal(t, "", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("empty_filename_continues", func(t *testing.T) {
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {archKeyForCurrent(t): {FileName: ""}},
			},
		}
		assert.Equal(t, "", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("template_render_success", func(t *testing.T) {
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {archKeyForCurrent(t): {FileName: "tool-{{.Version}}.tar.gz"}},
			},
		}
		assert.Equal(t, "tool-v1.2.3.tar.gz", resolveDownloadFileName(b, "v1.2.3"))
	})

	t.Run("template_render_failure_returns_empty", func(t *testing.T) {
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {archKeyForCurrent(t): {FileName: "tool-{{.Version}.tar.gz"}}, // unbalanced braces
			},
		}
		assert.Equal(t, "", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("aarch64_normalizes_to_arm64", func(t *testing.T) {
		if runtime.GOARCH != "arm64" {
			t.Skipf("skipping; needs runtime.GOARCH=arm64, got %s", runtime.GOARCH)
		}
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {"aarch64": {FileName: "tool-aarch64.tar.gz"}},
			},
		}
		assert.Equal(t, "tool-aarch64.tar.gz", resolveDownloadFileName(b, "v1.0.0"))
	})

	t.Run("x86_64_normalizes_to_amd64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skipf("skipping; needs runtime.GOARCH=amd64, got %s", runtime.GOARCH)
		}
		b := models.Binaries{
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {"x86_64": {FileName: "tool-x86_64.tar.gz"}},
			},
		}
		assert.Equal(t, "tool-x86_64.tar.gz", resolveDownloadFileName(b, "v1.0.0"))
	})
}

func TestFindProvider(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want int
	}{
		{"github_url", "https://github.com/owner/repo", GitHub},
		{"gitlab_url", "https://gitlab.com/owner/repo", Others},
		{"empty_url", "", Others},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := findProvider(models.Binaries{URL: tt.url})
			assert.Equal(t, tt.want, b.Provider)
		})
	}
}

// writeFileWithSHA writes content to a temp file and returns its path and SHA-256 hex.
func writeFileWithSHA(t *testing.T, content string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "payload.bin")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

func TestVerifyFile_InlineChecksum(t *testing.T) {
	t.Run("correct_sha256", func(t *testing.T) {
		path, hash := writeFileWithSHA(t, "hello world")
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			Sha:              models.ShaInfo{Checksum: hash, ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.True(t, ok)
		assert.NoError(t, err)
	})

	t.Run("default_shaType_when_empty", func(t *testing.T) {
		path, hash := writeFileWithSHA(t, "data")
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			Sha:              models.ShaInfo{Checksum: hash}, // ShaType empty defaults to sha256
		}
		ok, err := verifyFile(b)
		assert.True(t, ok)
		assert.NoError(t, err)
	})

	t.Run("wrong_sha256", func(t *testing.T) {
		path, _ := writeFileWithSHA(t, "hello world")
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			Sha:              models.ShaInfo{Checksum: "deadbeef", ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("checksum_case_insensitive", func(t *testing.T) {
		path, hash := writeFileWithSHA(t, "hello world")
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			Sha:              models.ShaInfo{Checksum: strings.ToUpper(hash), ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.True(t, ok)
		assert.NoError(t, err)
	})

	t.Run("unknown_shaType_errors", func(t *testing.T) {
		path, _ := writeFileWithSHA(t, "hello world")
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			Sha:              models.ShaInfo{Checksum: "abc", ShaType: "md5"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported sha type")
	})

	t.Run("no_checksum_no_url", func(t *testing.T) {
		b := models.Binaries{Name: "test"}
		ok, err := verifyFile(b)
		assert.True(t, ok)
		assert.NoError(t, err)
	})

	t.Run("missing_download_file_returns_error", func(t *testing.T) {
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: filepath.Join(t.TempDir(), "missing.bin"),
			Sha:              models.ShaInfo{Checksum: "abc", ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to calculate sha256")
	})
}

func TestVerifyFile_URL(t *testing.T) {
	t.Run("valid_sha_file", func(t *testing.T) {
		path, hash := writeFileWithSHA(t, "release payload")
		fileName := "release.tar.gz"

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(hash + "  " + fileName + "\n"))
		}))
		t.Cleanup(srv.Close)

		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			DownloadFileName: fileName,
			Sha:              models.ShaInfo{URL: srv.URL, ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.True(t, ok)
		assert.NoError(t, err)
	})

	t.Run("mismatched_sha", func(t *testing.T) {
		path, _ := writeFileWithSHA(t, "release payload")
		fileName := "release.tar.gz"

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  " + fileName + "\n"))
		}))
		t.Cleanup(srv.Close)

		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			DownloadFileName: fileName,
			Sha:              models.ShaInfo{URL: srv.URL, ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("empty_shaType_with_url", func(t *testing.T) {
		// No HTTP request expected — the empty-shaType check fires first.
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: "/does/not/matter",
			DownloadFileName: "x",
			Sha:              models.ShaInfo{URL: "http://127.0.0.1:0/never-called"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no sha type provided")
	})

	t.Run("unknown_shaType_with_url", func(t *testing.T) {
		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: "/does/not/matter",
			DownloadFileName: "x",
			Sha:              models.ShaInfo{URL: "http://127.0.0.1:0/never-called", ShaType: "md5"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported sha type")
	})

	t.Run("unparseable_sha_file", func(t *testing.T) {
		path, _ := writeFileWithSHA(t, "release payload")
		fileName := "release.tar.gz"

		// Multi-line content with spaces that doesn't match the file name and
		// doesn't fall through the single-hash heuristic.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("abc123  some-other-file.tar.gz\ndef456  yet-another.tar.gz\n"))
		}))
		t.Cleanup(srv.Close)

		b := models.Binaries{
			Name:             "test",
			DownloadFilePath: path,
			DownloadFileName: fileName,
			Sha:              models.ShaInfo{URL: srv.URL, ShaType: "sha256"},
		}
		ok, err := verifyFile(b)
		assert.False(t, ok)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse checksum")
	})
}

func TestMoveFiles(t *testing.T) {
	t.Run("simple_copy_with_chmod", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "install")
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "tool"), []byte("#!/bin/sh\n"), 0o600))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: installDir,
			Files:           []models.File{{FileName: "tool", CopyIt: true}},
		}
		require.NoError(t, moveFiles(&b))

		dst := filepath.Join(installDir, "tool")
		info, err := os.Stat(dst)
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&0o111, "destination should be executable")
	})

	t.Run("rename_to", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "tool"), []byte("data"), 0o644))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: installDir,
			Files:           []models.File{{FileName: "tool", RenameTo: "renamed-tool", CopyIt: true}},
		}
		require.NoError(t, moveFiles(&b))

		_, err := os.Stat(filepath.Join(installDir, "renamed-tool"))
		assert.NoError(t, err)
		_, err = os.Stat(filepath.Join(installDir, "tool"))
		assert.True(t, os.IsNotExist(err), "original name should not exist at install location")
	})

	t.Run("source_path_used", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(downloadDir, "nested", "bin"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "nested", "bin", "tool"), []byte("data"), 0o644))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: installDir,
			Files: []models.File{{
				FileName:   "tool",
				SourcePath: "nested/bin/tool",
				CopyIt:     true,
			}},
		}
		require.NoError(t, moveFiles(&b))

		_, err := os.Stat(filepath.Join(installDir, "tool"))
		assert.NoError(t, err)
	})

	t.Run("versioned_subdirectory_fallback", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := t.TempDir()

		// Mimic an archive that extracts into a versioned folder named after
		// FileNameWithoutExtension(DownloadFileName).
		downloadFileName := "tool-1.0.0.tar.gz"
		extracted := utils.FileNameWithoutExtension(downloadFileName)
		require.NoError(t, os.MkdirAll(filepath.Join(downloadDir, extracted), 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(downloadDir, extracted, "tool"),
			[]byte("data"), 0o644,
		))

		b := models.Binaries{
			Name:             "test",
			DownloadFolder:   downloadDir,
			DownloadFileName: downloadFileName,
			InstallLocation:  installDir,
			Files:            []models.File{{FileName: "tool", CopyIt: true}},
		}
		require.NoError(t, moveFiles(&b))

		_, err := os.Stat(filepath.Join(installDir, "tool"))
		assert.NoError(t, err)
	})

	t.Run("tilde_expansion", func(t *testing.T) {
		fakeHome := t.TempDir()
		t.Setenv("HOME", fakeHome)

		downloadDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "tool"), []byte("data"), 0o644))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: "~/binstall-test-bin",
			Files:           []models.File{{FileName: "tool", CopyIt: true}},
		}
		require.NoError(t, moveFiles(&b))

		expectedDst := filepath.Join(fakeHome, "binstall-test-bin", "tool")
		_, err := os.Stat(expectedDst)
		assert.NoError(t, err)
		// moveFiles mutates InstallLocation to the expanded path.
		assert.Equal(t, filepath.Join(fakeHome, "binstall-test-bin"), b.InstallLocation)
	})

	t.Run("mkdir_install_location", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := filepath.Join(t.TempDir(), "deeply", "nested", "bin")
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "tool"), []byte("data"), 0o644))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: installDir,
			Files:           []models.File{{FileName: "tool", CopyIt: true}},
		}
		require.NoError(t, moveFiles(&b))

		_, err := os.Stat(installDir)
		assert.NoError(t, err)
	})

	t.Run("copyIt_false_skips_move", func(t *testing.T) {
		downloadDir := t.TempDir()
		installDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(downloadDir, "tool"), []byte("data"), 0o644))

		b := models.Binaries{
			Name:            "test",
			DownloadFolder:  downloadDir,
			InstallLocation: installDir,
			Files:           []models.File{{FileName: "tool", CopyIt: false}},
		}
		require.NoError(t, moveFiles(&b))

		_, err := os.Stat(filepath.Join(installDir, "tool"))
		assert.True(t, os.IsNotExist(err), "file should not be copied when CopyIt is false")
	})
}

// ---------------------------------------------------------------------------
// Helpers for exec/HTTP/archive tests
// ---------------------------------------------------------------------------

// writeShellScript writes an executable POSIX shell script under dir and
// returns its path. The script body is wrapped with `#!/bin/sh` so it is
// runnable on Linux/macOS.
func writeShellScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script-based tests are POSIX-only")
	}
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return path
}

// makeTarGz writes a gzip-compressed tar archive at dst containing the given
// files (name -> content). All entries are mode 0755. Writers are closed in
// order with their errors asserted so flush/finalize failures surface as test
// failures instead of silently producing a corrupted archive.
func makeTarGz(t *testing.T, dst string, files map[string]string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(dst), 0o755))
	f, err := os.Create(dst)
	require.NoError(t, err)

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for name, content := range files {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	require.NoError(t, f.Close())
}

// uniqueTempName returns a unique tempdir-safe binary name derived from t.Name.
// downloadFile builds its own folder under os.TempDir(), so this guards against
// cross-test collisions. The folder is removed on cleanup.
func uniqueTempName(t *testing.T) string {
	t.Helper()
	name := "binstall-test-" + strings.ReplaceAll(t.Name(), "/", "_")
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Join(os.TempDir(), name)) })
	return name
}

// withGitHubServer swaps the package-level newGitHubClient to point at an
// httptest server that serves a single repository release JSON. The handler
// matches the latest-release path to keep the test surface tight; everything
// else 404s so accidental calls fail loudly.
func withGitHubServer(t *testing.T, tagName string, assets []*github.ReleaseAsset) *httptest.Server {
	t.Helper()
	rel := &github.RepositoryRelease{
		TagName: github.Ptr(tagName),
		Assets:  assets,
	}
	body, err := json.Marshal(rel)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	old := newGitHubClient
	newGitHubClient = func(token string) (*github.Client, error) {
		return github.NewClient(github.WithEnterpriseURLs(srv.URL+"/", srv.URL+"/"))
	}
	t.Cleanup(func() { newGitHubClient = old })
	return srv
}

// currentOSArchAssetName builds a release asset name that FigureOutOSAndArch
// will resolve to the host's runtime.GOOS / runtime.GOARCH.
func currentOSArchAssetName(suffix string) string {
	return fmt.Sprintf("tool-%s-%s.%s", runtime.GOOS, runtime.GOARCH, suffix)
}

// ---------------------------------------------------------------------------
// getCurrentVersion
// ---------------------------------------------------------------------------

func TestGetCurrentVersion(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		dir := t.TempDir()
		writeShellScript(t, dir, "mytool", `echo "mytool version 1.2.3"`)
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			Files: []models.File{{
				FileName:     "mytool",
				CheckVersion: true,
				VersionCommand: models.VersionCommand{
					Args:         "--version",
					RegexVersion: `\d+\.\d+\.\d+`,
				},
			}},
		}
		got, err := getCurrentVersion(b)
		require.NoError(t, err)
		assert.Equal(t, "1.2.3", got.CurrentVersion)
	})

	t.Run("binary_not_found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // empty PATH dir

		b := models.Binaries{
			Files: []models.File{{
				FileName:       "definitely-missing-binary",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+`},
			}},
		}
		_, err := getCurrentVersion(b)
		require.Error(t, err)
	})

	t.Run("invalid_regex_returns_error", func(t *testing.T) {
		dir := t.TempDir()
		writeShellScript(t, dir, "mytool", `echo "1.2.3"`)
		t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: "["},
			}},
		}
		_, err := getCurrentVersion(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to compile the regex")
	})

	t.Run("no_checkVersion_file_returns_b_unchanged", func(t *testing.T) {
		b := models.Binaries{
			Files: []models.File{{FileName: "noop", CheckVersion: false}},
		}
		got, err := getCurrentVersion(b)
		require.NoError(t, err)
		assert.Equal(t, "", got.CurrentVersion)
	})
}

// ---------------------------------------------------------------------------
// verifyNewBin
// ---------------------------------------------------------------------------

func TestVerifyNewBin(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		installDir := t.TempDir()
		writeShellScript(t, installDir, "mytool", `echo "1.2.3"`)
		t.Setenv("PATH", installDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			InstallLocation: installDir,
			NewVersion:      "1.2.3",
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		assert.NoError(t, verifyNewBin(b))
	})

	t.Run("binary_missing_at_install_location", func(t *testing.T) {
		installDir := t.TempDir() // empty
		t.Setenv("PATH", installDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			InstallLocation: installDir,
			NewVersion:      "1.2.3",
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		err := verifyNewBin(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "binary not found at expected location")
	})

	t.Run("version_mismatch", func(t *testing.T) {
		installDir := t.TempDir()
		writeShellScript(t, installDir, "mytool", `echo "1.0.0"`)
		t.Setenv("PATH", installDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			InstallLocation: installDir,
			NewVersion:      "1.2.3",
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		err := verifyNewBin(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version mismatch")
	})

	t.Run("no_checkVersion_file_skips", func(t *testing.T) {
		b := models.Binaries{
			InstallLocation: t.TempDir(),
			Files:           []models.File{{FileName: "noop", CheckVersion: false}},
		}
		assert.NoError(t, verifyNewBin(b))
	})
}

// ---------------------------------------------------------------------------
// downloadFile
// ---------------------------------------------------------------------------

func TestDownloadFile(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		body := "release payload bytes"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)

		b := models.Binaries{
			Name:             uniqueTempName(t),
			DownloadFileName: "tool.tar.gz",
			DownloadURL:      srv.URL + "/tool.tar.gz",
		}
		got, err := downloadFile(b)
		require.NoError(t, err)

		// Folder/path are derived from os.TempDir + b.Name.
		assert.Equal(t, filepath.Join(os.TempDir(), b.Name), got.DownloadFolder)
		assert.Equal(t, filepath.Join(got.DownloadFolder, "tool.tar.gz"), got.DownloadFilePath)

		data, err := os.ReadFile(got.DownloadFilePath)
		require.NoError(t, err)
		assert.Equal(t, body, string(data))
	})
}

// ---------------------------------------------------------------------------
// uncompressFile
// ---------------------------------------------------------------------------

func TestUncompressFile(t *testing.T) {
	t.Run("happy_path_targz", func(t *testing.T) {
		dir := t.TempDir()
		archive := filepath.Join(dir, "release.tar.gz")
		makeTarGz(t, archive, map[string]string{
			"tool": "binary contents",
		})

		b := models.Binaries{
			Name:             "test",
			DownloadFolder:   dir,
			DownloadFilePath: archive,
			DownloadFileName: "release.tar.gz",
			ContentType:      "application/gzip",
		}
		require.NoError(t, uncompressFile(b))

		_, err := os.Stat(filepath.Join(dir, "tool"))
		assert.NoError(t, err)
	})

	t.Run("empty_filename_returns_error", func(t *testing.T) {
		b := models.Binaries{Name: "test"} // DownloadFileName empty
		err := uncompressFile(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no file to uncompress")
	})

	t.Run("missing_file_returns_error", func(t *testing.T) {
		b := models.Binaries{
			Name:             "test",
			DownloadFolder:   t.TempDir(),
			DownloadFilePath: filepath.Join(t.TempDir(), "missing.tar.gz"),
			DownloadFileName: "missing.tar.gz",
			ContentType:      "application/gzip",
		}
		err := uncompressFile(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to detect the file type")
	})

	t.Run("disallowed_media_type", func(t *testing.T) {
		// Build a real gzip archive (so mimetype detection passes), but report
		// a content type that isn't in allowedMediaTypes.
		dir := t.TempDir()
		archive := filepath.Join(dir, "release.tar.gz")
		makeTarGz(t, archive, map[string]string{"tool": "data"})

		b := models.Binaries{
			Name:             "test",
			DownloadFolder:   dir,
			DownloadFilePath: archive,
			DownloadFileName: "release.tar.gz",
			ContentType:      "application/x-totally-made-up",
		}
		err := uncompressFile(b)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file type not supported")
	})

	t.Run("unparseable_content_type", func(t *testing.T) {
		dir := t.TempDir()
		archive := filepath.Join(dir, "release.tar.gz")
		makeTarGz(t, archive, map[string]string{"tool": "data"})

		b := models.Binaries{
			Name:             "test",
			DownloadFolder:   dir,
			DownloadFilePath: archive,
			DownloadFileName: "release.tar.gz",
			ContentType:      "not a media type",
		}
		require.Error(t, uncompressFile(b))
	})
}

// ---------------------------------------------------------------------------
// checkForNewVersion
// ---------------------------------------------------------------------------

func TestCheckForNewVersion(t *testing.T) {
	t.Run("auto_detected_asset", func(t *testing.T) {
		assetName := currentOSArchAssetName("tar.gz")
		downloadURL := "https://example.test/" + assetName
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr(downloadURL),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL:      "https://github.com/owner/repo",
			Provider: GitHub,
		}
		got, err := checkForNewVersion(b)
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", got.NewVersion)
		assert.Equal(t, downloadURL, got.DownloadURL)
		assert.Equal(t, assetName, got.DownloadFileName)
		assert.Equal(t, runtime.GOOS, got.OsInfo.OS)
		assert.Equal(t, runtime.GOARCH, got.OsInfo.Arch)
	})

	t.Run("configured_download_filename_match", func(t *testing.T) {
		// Asset name doesn't include OS/arch keywords — auto-detect would skip
		// it. We rely on the Download config to pick it up.
		assetName := "release-v1.2.3-custom.tar.gz"
		downloadURL := "https://example.test/" + assetName
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr(downloadURL),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL:      "https://github.com/owner/repo",
			Provider: GitHub,
			Download: map[string]map[string]models.DownloadArchInfo{
				runtime.GOOS: {archKeyForCurrent(t): {FileName: "release-{{.Version}}-custom.tar.gz"}},
			},
		}
		got, err := checkForNewVersion(b)
		require.NoError(t, err)
		assert.Equal(t, downloadURL, got.DownloadURL)
		assert.Equal(t, assetName, got.DownloadFileName)
	})

	t.Run("ignores_disallowed_extensions", func(t *testing.T) {
		// The .deb asset matches OS/arch but should be skipped via ignoreFileExt.
		debName := fmt.Sprintf("tool-%s-%s.deb", runtime.GOOS, runtime.GOARCH)
		gzName := currentOSArchAssetName("tar.gz")
		gzURL := "https://example.test/" + gzName
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{
			{Name: github.Ptr(debName), BrowserDownloadURL: github.Ptr("https://example.test/" + debName), ContentType: github.Ptr("application/x-debian-package")},
			{Name: github.Ptr(gzName), BrowserDownloadURL: github.Ptr(gzURL), ContentType: github.Ptr("application/gzip")},
		})

		b := models.Binaries{URL: "https://github.com/owner/repo", Provider: GitHub}
		got, err := checkForNewVersion(b)
		require.NoError(t, err)
		assert.Equal(t, gzName, got.DownloadFileName)
	})

	t.Run("no_matching_asset_returns_ErrNetBinaryNotFound", func(t *testing.T) {
		// Asset is for an OS/arch we are definitely not running on.
		bogusName := "tool-plan9-mips.tar.gz"
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(bogusName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + bogusName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{URL: "https://github.com/owner/repo", Provider: GitHub}
		_, err := checkForNewVersion(b)
		require.Error(t, err)
	})

	t.Run("non_github_provider_returns_ErrNetBinaryNotFound", func(t *testing.T) {
		b := models.Binaries{URL: "https://gitlab.com/owner/repo", Provider: Others}
		_, err := checkForNewVersion(b)
		require.Error(t, err)
	})
}

// ---------------------------------------------------------------------------
// CheckUpdates
// ---------------------------------------------------------------------------

func TestCheckUpdates(t *testing.T) {
	t.Run("update_available", func(t *testing.T) {
		// Local binary reports 1.0.0; release reports v1.2.3.
		bindir := t.TempDir()
		writeShellScript(t, bindir, "mytool", `echo "mytool 1.0.0"`)
		t.Setenv("PATH", bindir+string(os.PathListSeparator)+os.Getenv("PATH"))

		assetName := currentOSArchAssetName("tar.gz")
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + assetName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/owner/repo",
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.True(t, got.UpdatesAvailable)
		assert.Equal(t, "1.0.0", got.CurrentVersion)
		assert.Equal(t, "v1.2.3", got.NewVersion)
	})

	t.Run("no_update", func(t *testing.T) {
		bindir := t.TempDir()
		writeShellScript(t, bindir, "mytool", `echo "mytool 1.2.3"`)
		t.Setenv("PATH", bindir+string(os.PathListSeparator)+os.Getenv("PATH"))

		assetName := currentOSArchAssetName("tar.gz")
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + assetName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/owner/repo",
			Files: []models.File{{
				FileName:       "mytool",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.False(t, got.UpdatesAvailable)
	})

	t.Run("binary_not_installed_marks_install", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir()) // no binary on PATH

		assetName := currentOSArchAssetName("tar.gz")
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + assetName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/owner/repo",
			Files: []models.File{{
				FileName:       "definitely-missing-binary",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.True(t, got.UpdatesAvailable)
		assert.Equal(t, "Not Found", got.CurrentVersion)
	})

	t.Run("letter_suffix_release_is_post_release", func(t *testing.T) {
		// Regression: tmux 3.6a is a post-release patch of 3.6, so an installed
		// 3.6 must be detected as out-of-date relative to a 3.6a release.
		// Without NormalizeLetterSuffix, hashicorp/go-version would treat 3.6a
		// as a pre-release ("3.6.0-a") and rank it below plain 3.6.
		bindir := t.TempDir()
		writeShellScript(t, bindir, "tmux", `echo "tmux 3.6"`)
		t.Setenv("PATH", bindir+string(os.PathListSeparator)+os.Getenv("PATH"))

		assetName := currentOSArchAssetName("tar.gz")
		withGitHubServer(t, "3.6a", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + assetName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/tmux/tmux",
			Files: []models.File{{
				FileName:     "tmux",
				CheckVersion: true,
				VersionCommand: models.VersionCommand{
					Args:         "-V",
					RegexVersion: `\d+(?:\.\d+)+[a-z]?`,
				},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.True(t, got.UpdatesAvailable, "3.6a should be detected as newer than 3.6")
		assert.Equal(t, "3.6", got.CurrentVersion)
		assert.Equal(t, "3.6a", got.NewVersion)
	})

	t.Run("letter_suffix_already_installed", func(t *testing.T) {
		// Same letter on both sides should report no update.
		bindir := t.TempDir()
		writeShellScript(t, bindir, "tmux", `echo "tmux 3.6a"`)
		t.Setenv("PATH", bindir+string(os.PathListSeparator)+os.Getenv("PATH"))

		assetName := currentOSArchAssetName("tar.gz")
		withGitHubServer(t, "3.6a", []*github.ReleaseAsset{{
			Name:               github.Ptr(assetName),
			BrowserDownloadURL: github.Ptr("https://example.test/" + assetName),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/tmux/tmux",
			Files: []models.File{{
				FileName:     "tmux",
				CheckVersion: true,
				VersionCommand: models.VersionCommand{
					Args:         "-V",
					RegexVersion: `\d+(?:\.\d+)+[a-z]?`,
				},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.False(t, got.UpdatesAvailable)
	})

	t.Run("binary_not_installed_no_matching_asset_returns_empty", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		// Asset is for an unrelated OS/arch.
		withGitHubServer(t, "v1.2.3", []*github.ReleaseAsset{{
			Name:               github.Ptr("tool-plan9-mips.tar.gz"),
			BrowserDownloadURL: github.Ptr("https://example.test/none"),
			ContentType:        github.Ptr("application/gzip"),
		}})

		b := models.Binaries{
			URL: "https://github.com/owner/repo",
			Files: []models.File{{
				FileName:       "definitely-missing-binary",
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+`},
			}},
		}
		got, err := CheckUpdates(b)
		require.NoError(t, err)
		assert.Equal(t, models.Binaries{}, got)
	})
}

// ---------------------------------------------------------------------------
// DownloadAndMoveFiles (end-to-end through downloadFile -> verifyFile ->
// uncompressFile -> moveFiles -> verifyNewBin)
// ---------------------------------------------------------------------------

func TestDownloadAndMoveFiles(t *testing.T) {
	t.Run("happy_path_targz", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("end-to-end install relies on POSIX shell scripts")
		}

		// Build a tar.gz containing a shell-script "tool" that prints a version.
		archiveDir := t.TempDir()
		archivePath := filepath.Join(archiveDir, "release.tar.gz")
		makeTarGz(t, archivePath, map[string]string{
			"tool": "#!/bin/sh\necho \"1.2.3\"",
		})

		// Serve the archive over HTTP.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, archivePath)
		}))
		t.Cleanup(srv.Close)

		installDir := t.TempDir()
		t.Setenv("PATH", installDir+string(os.PathListSeparator)+os.Getenv("PATH"))

		b := models.Binaries{
			Name:             uniqueTempName(t),
			URL:              "https://github.com/owner/repo",
			NewVersion:       "1.2.3",
			DownloadURL:      srv.URL + "/release.tar.gz",
			DownloadFileName: "release.tar.gz",
			ContentType:      "application/gzip",
			InstallLocation:  installDir,
			Files: []models.File{{
				FileName:       "tool",
				CopyIt:         true,
				CheckVersion:   true,
				VersionCommand: models.VersionCommand{Args: "--version", RegexVersion: `\d+\.\d+\.\d+`},
			}},
		}
		require.NoError(t, DownloadAndMoveFiles(b))

		// Tool should be installed and executable.
		info, err := os.Stat(filepath.Join(installDir, "tool"))
		require.NoError(t, err)
		assert.NotZero(t, info.Mode()&0o111)
	})

	t.Run("download_error_propagates", func(t *testing.T) {
		// resty against an unreachable port: SetOutput still writes a (likely
		// zero-byte) file, so this exercises the URL-error path of resty/Get.
		// Use a closed listener URL.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		srv.Close() // immediately close so the URL is unreachable

		b := models.Binaries{
			Name:             uniqueTempName(t),
			DownloadURL:      srv.URL,
			DownloadFileName: "x.tar.gz",
			InstallLocation:  t.TempDir(),
		}
		err := DownloadAndMoveFiles(b)
		require.Error(t, err)
	})
}
