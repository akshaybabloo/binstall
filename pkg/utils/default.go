package utils

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

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
