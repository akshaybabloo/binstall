package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp/syntax"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/akshaybabloo/binstall/models"
)

func TestExpandGitHubURL(t *testing.T) {
	info := models.GitHubInfo{
		Owner: "akshaybabloo",
		Repo:  "gollahalli.com",
	}
	url := "https://hithub.com/akshaybabloo/gollahalli.com"
	hubURL := ExpandGitHubURL(url)
	assert.Equal(t, info, hubURL)
}

func TestFigureOutOSAndArch(t *testing.T) {
	type args struct {
		f string
	}
	tests := []struct {
		name string
		args args
		want models.OSArch
	}{
		{name: "unknown", args: args{f: ""}, want: models.OSArch{
			OS:   "unknown",
			Arch: "unknown",
		}},
		{name: "linux amd64", args: args{f: "linux_amd64"}, want: models.OSArch{
			OS:   "linux",
			Arch: "amd64",
		}},
		{name: "darwin amd64", args: args{f: "darwin_amd64"}, want: models.OSArch{
			OS:   "darwin",
			Arch: "amd64",
		}},
		{name: "windows amd64", args: args{f: "windows_amd64"}, want: models.OSArch{
			OS:   "windows",
			Arch: "amd64",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, FigureOutOSAndArch(tt.args.f), "FigureOutOSAndArch(%v)", tt.args.f)
		})
	}
}

func TestCalculateSHA256(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "sha256test")
	require.NoError(t, err, "Failed to create temp directory")
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"EmptyFile", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"SmallFile", "Hello, World!", "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"},
		{"LargerFile", string(make([]byte, 1024*1024)), ""}, // 1MB of zero bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test file
			filePath := filepath.Join(tempDir, tt.name)
			err := os.WriteFile(filePath, []byte(tt.content), 0666)
			require.NoError(t, err, "Failed to create test file")

			// Calculate expected SHA256 for LargerFile
			if tt.name == "LargerFile" {
				h := sha256.New()
				h.Write([]byte(tt.content))
				tt.expected = hex.EncodeToString(h.Sum(nil))
			}

			// Run the function
			got, err := CalculateSHA256(filePath)
			assert.NoError(t, err, "CalculateSHA256() should not return an error")
			assert.Equal(t, tt.expected, got, "CalculateSHA256() returned unexpected result")
		})
	}

	// Test non-existent file
	t.Run("NonExistentFile", func(t *testing.T) {
		_, err := CalculateSHA256(filepath.Join(tempDir, "non-existent-file"))
		assert.Error(t, err, "CalculateSHA256() should return an error for non-existent file")
	})
}

func TestParseYaml(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name string
		args args
		want models.Binaries
	}{
		{name: "empty", args: args{s: []byte{}}, want: models.Binaries{}},
		{name: "invalid", args: args{s: []byte("invalid")}, want: models.Binaries{}},
		{name: "valid", args: args{s: []byte("name: test")}, want: models.Binaries{Name: "test"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseYaml(tt.args.s)
			if tt.name == "invalid" {
				assert.Error(t, err, "ParseYaml() should return an error")
				return
			}
			assert.NoError(t, err, "ParseYaml() should not return an error")
			assert.Equalf(t, tt.want, got, "ParseYaml(%v)", tt.args.s)
		})
	}
}

func TestFileNameWithoutExtension(t *testing.T) {
	type args struct {
		fileName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "no extension", args: args{fileName: "test"}, want: "test"},
		{name: "with extension", args: args{fileName: "test.zip"}, want: "test"},
		{name: "with multiple extensions", args: args{fileName: "test.tar.gz"}, want: "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, FileNameWithoutExtension(tt.args.fileName), "FileNameWithoutExtension(%v)", tt.args.fileName)
		})
	}
}

func TestParseSHAFile(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		filename string
		expected string
	}{
		{
			name:     "GNU coreutils format (two spaces)",
			content:  "abc123def456  myfile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Binary mode format",
			content:  "abc123def456 *myfile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Single space format",
			content:  "abc123def456 myfile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Multi-line file",
			content:  "aaa111  file1.tar.gz\nbbb222  file2.tar.gz\nccc333  file3.tar.gz",
			filename: "file2.tar.gz",
			expected: "bbb222",
		},
		{
			name:     "Hash only (single file checksum)",
			content:  "abc123def456",
			filename: "anything.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Case insensitive filename match",
			content:  "ABC123DEF456  MyFile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Case insensitive hash returned",
			content:  "ABC123DEF456  myfile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
		{
			name:     "Not found in multi-line",
			content:  "abc123  other.tar.gz",
			filename: "myfile.tar.gz",
			expected: "",
		},
		{
			name:     "Empty content",
			content:  "",
			filename: "myfile.tar.gz",
			expected: "",
		},
		{
			name:     "With path prefix in SHA file",
			content:  "abc123def456  ./dist/myfile.tar.gz",
			filename: "myfile.tar.gz",
			expected: "abc123def456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseSHAFile(tt.content, tt.filename)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func FuzzExtractVersion(f *testing.F) {
	f.Add("app version v1.2", "v(\\d+\\.\\d+)")
	f.Add("1.2.3", "\\d+\\.\\d+\\.\\d+")
	f.Add("the version 10 is the latest", "version (\\d+)")
	f.Add("invalid regex", "[") // A known-bad regex pattern
	f.Add("", "")               // Empty inputs

	f.Fuzz(func(t *testing.T, inputString string, regexPattern string) {
		t.Parallel()
		_, err := ExtractVersion(inputString, regexPattern)
		if err != nil {
			var syntaxError *syntax.Error
			if !errors.As(err, &syntaxError) {
				t.Errorf("Expected a regexp.Error but got %T", err)
			}
		}
	})
}

func TestNormalizeArch(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"amd64", "amd64"},
		{"x86_64", "amd64"},
		{"arm64", "arm64"},
		{"aarch64", "arm64"},
		{"386", "386"},
		{"i386", "386"},
		{"i686", "386"},
		{"AARCH64", "arm64"},
		{"X86_64", "amd64"},
		{"riscv64", "riscv64"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, NormalizeArch(tt.input))
		})
	}
}

func TestRenderDownloadTemplate(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "with version template",
			tmpl:    "bat-{{.Version}}-x86_64-unknown-linux-gnu.tar.gz",
			version: "v0.24.0",
			want:    "bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz",
		},
		{
			name:    "no template syntax",
			tmpl:    "bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz",
			version: "v0.24.0",
			want:    "bat-v0.24.0-x86_64-unknown-linux-gnu.tar.gz",
		},
		{
			name:    "empty version",
			tmpl:    "bat-{{.Version}}-linux.tar.gz",
			version: "",
			want:    "bat--linux.tar.gz",
		},
		{
			name:    "invalid template",
			tmpl:    "bat-{{.Version}-linux.tar.gz",
			version: "v1.0",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderDownloadTemplate(tt.tmpl, tt.version)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		s    []string
		e    string
		want bool
	}{
		{"in_slice", []string{"a", "b", "c"}, "b", true},
		{"not_in_slice", []string{"a", "b", "c"}, "z", false},
		{"empty_slice", nil, "a", false},
		{"empty_string_in_slice_of_empty", []string{""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Contains(tt.s, tt.e))
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		regex   string
		want    string
		wantErr bool
	}{
		{name: "simple_match", input: "1.2.3", regex: `\d+\.\d+\.\d+`, want: "1.2.3"},
		{name: "two_token_format", input: "Something v1.0.0", regex: `Something v\d+\.\d+\.\d+`, want: "v1.0.0"},
		{name: "no_match_returns_empty_no_error", input: "no version here", regex: `v\d+`, want: ""},
		{name: "invalid_regex_returns_error", input: "anything", regex: "[", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractVersion(tt.input, tt.regex)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseYamlWithDownload(t *testing.T) {
	yamlContent := []byte(`
name: "Bat"
url: "https://github.com/sharkdp/bat"
installLocation: "~/bin"
download:
  linux:
    amd64:
      fileName: "bat-{{.Version}}-x86_64-unknown-linux-gnu.tar.gz"
    aarch64:
      fileName: "bat-{{.Version}}-aarch64-unknown-linux-gnu.tar.gz"
files:
  - fileName: "bat"
    copyIt: true
    checkVersion: true
    versionCommand:
      args: "--version"
      regexVersion: "\\d+\\.\\d+\\.\\d+"
`)
	b, err := ParseYaml(yamlContent)
	require.NoError(t, err)
	assert.Equal(t, "Bat", b.Name)
	assert.NotNil(t, b.Download)
	assert.Contains(t, b.Download, "linux")
	assert.Contains(t, b.Download["linux"], "amd64")
	assert.Equal(t, "bat-{{.Version}}-x86_64-unknown-linux-gnu.tar.gz", b.Download["linux"]["amd64"].FileName)
	assert.Contains(t, b.Download["linux"], "aarch64")
	assert.Equal(t, "bat-{{.Version}}-aarch64-unknown-linux-gnu.tar.gz", b.Download["linux"]["aarch64"].FileName)
}
