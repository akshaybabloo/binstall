package utils

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/goccy/go-yaml"

	"github.com/akshaybabloo/binstall/models"
)

// ParseYaml parses the yaml string and returns the models.Binaries
func ParseYaml(s []byte) (models.Binaries, error) {
	var b models.Binaries
	err := yaml.Unmarshal(s, &b)
	if err != nil {
		return models.Binaries{}, err
	}
	return b, nil
}

// ExpandGitHubURL expands the GitHub URL and returns the models.GitHubInfo
func ExpandGitHubURL(url string) models.GitHubInfo {
	var github models.GitHubInfo
	d := strings.Split(url, "/")
	github.Owner = d[3]
	github.Repo = d[4]
	return github
}

// FigureOutOSAndArch figures out the OS and Arch of the system
func FigureOutOSAndArch(f string) models.OSArch {
	var osArch models.OSArch

	f = strings.ToLower(f)

	if strings.Contains(f, "linux") {
		osArch.OS = "linux"
	} else if strings.Contains(f, "darwin") {
		osArch.OS = "darwin"
	} else if strings.Contains(f, "windows") {
		osArch.OS = "windows"
	} else {
		osArch.OS = "unknown"
	}

	if strings.Contains(f, "amd64") || strings.Contains(f, "x86_64") {
		osArch.Arch = "amd64"
	} else if strings.Contains(f, "386") {
		osArch.Arch = "386"
	} else if strings.Contains(f, "arm64") || strings.Contains(f, "aarch64") {
		osArch.Arch = "arm64"
	} else {
		osArch.Arch = "unknown"
	}

	return osArch
}

// CalculateSHA256 calculates the SHA256 checksum of a file
func CalculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, bufio.NewReader(file)); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ParseSHAFile extracts the checksum for a given filename from SHA file content.
// Handles formats like:
//   - "hash  filename" (GNU coreutils)
//   - "hash *filename" (binary mode)
//   - "hash filename" (single space)
//   - Multi-line files with multiple entries
//
// Returns the checksum (lowercase) or empty string if not found.
func ParseSHAFile(content string, targetFilename string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	targetFilename = strings.ToLower(filepath.Base(targetFilename))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse "hash  filename" or "hash *filename" format
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			hash := strings.ToLower(parts[0])
			filename := strings.ToLower(strings.TrimPrefix(parts[1], "*"))
			filename = filepath.Base(filename)

			if filename == targetFilename {
				return hash
			}
		} else if len(parts) == 1 {
			// Single hash on a line - return it for single-file checksum files
			return strings.ToLower(parts[0])
		}
	}

	// If no match found but content looks like a single hash, return it
	content = strings.TrimSpace(content)
	if !strings.Contains(content, "\n") && !strings.Contains(content, " ") {
		return strings.ToLower(content)
	}

	return ""
}

// Contains checks if a string is in a slice
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// FileNameWithoutExtension returns the file name without the extension
func FileNameWithoutExtension(fileName string) string {
	baseName := filepath.Base(fileName)
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	if strings.HasSuffix(name, ".tar") {
		name = strings.TrimSuffix(name, ".tar")
	}
	return name
}

// ExtractVersion extracts the version from a string using a regex pattern
func ExtractVersion(version, regex string) (string, error) {
	r, err := regexp.Compile(regex)
	if err != nil {
		return "", err
	}

	matches := r.FindStringSubmatch(version)
	if len(matches) > 0 {
		matched := strings.TrimSpace(matches[0])

		regex, err := regexp.Compile("\\s+")
		if err != nil {
			return "", err
		}
		splitStr := regex.Split(matched, -1)
		if len(splitStr) > 1 {
			// If the version is in the format "Somethis v1.0.0"
			matched = splitStr[1]
		} else {
			matched = splitStr[0]
		}
		return matched, nil
	}
	return "", nil
}

// letterSuffixRe matches a numeric version with a single trailing lowercase
// letter (e.g. "3.6a", "v1.1.1k"). Group 1 is the numeric part (with optional
// "v"), group 2 is the suffix letter.
var letterSuffixRe = regexp.MustCompile(`^(v?\d+(?:\.\d+)+)([a-z])$`)

// bPrefixBuildRe matches tags like "b9993" used by some projects (e.g. llama.cpp).
// Group 1 is the numeric build number.
var bPrefixBuildRe = regexp.MustCompile(`^[bB](\d+)$`)

// NormalizeLetterSuffix converts a version string with a single trailing
// lowercase letter into a numeric form with the letter position appended as
// an extra patch segment, e.g. "3.6a" -> "3.6.1", "1.1.1k" -> "1.1.1.11".
//
// This makes letter-suffix patch releases (used by tmux, OpenSSL, and other
// projects) order correctly under standard semver comparison: 3.6 < 3.6a <
// 3.6b < 3.7. Without this conversion, hashicorp/go-version interprets the
// letter as a semver pre-release and orders 3.6a < 3.6, which is the
// opposite of these projects' conventions.
//
// Inputs without a trailing letter, with multiple trailing letters, or with
// a hyphen-separated semver pre-release (e.g. "1.0.0-beta1") are returned
// unchanged.
func NormalizeLetterSuffix(v string) string {
	trimmed := strings.TrimSpace(v)
	if m := bPrefixBuildRe.FindStringSubmatch(trimmed); m != nil {
		return m[1]
	}
	m := letterSuffixRe.FindStringSubmatch(trimmed)
	if m == nil {
		return v
	}
	pos := int(m[2][0]-'a') + 1
	return fmt.Sprintf("%s.%d", m[1], pos)
}

// NormalizeArch normalizes architecture names to Go's runtime.GOARCH values
func NormalizeArch(arch string) string {
	switch strings.ToLower(arch) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	case "386", "i386", "i686":
		return "386"
	default:
		return strings.ToLower(arch)
	}
}

// TemplateData holds the data available to download fileName templates
type TemplateData struct {
	Version string
}

// RenderDownloadTemplate renders a Go text/template string with the given version.
// Returns the input unchanged if it contains no template syntax.
func RenderDownloadTemplate(tmpl string, version string) (string, error) {
	t, err := template.New("download").Parse(tmpl)
	if err != nil {
		return "", fmt.Errorf("failed to parse download template %q: %w", tmpl, err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, TemplateData{Version: version}); err != nil {
		return "", fmt.Errorf("failed to render download template %q: %w", tmpl, err)
	}
	return buf.String(), nil
}
