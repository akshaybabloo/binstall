package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/akshaybabloo/binstall/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{name: "with extension", args: args{fileName: "test.txt"}, want: "test"},
		{name: "with multiple extensions", args: args{fileName: "test.txt.gz"}, want: "test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, FileNameWithoutExtension(tt.args.fileName), "FileNameWithoutExtension(%v)", tt.args.fileName)
		})
	}
}
