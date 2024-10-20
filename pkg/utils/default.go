package utils

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/akshaybabloo/binstall/models"
	"github.com/goccy/go-yaml"
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
	for filepath.Ext(name) != "" {
		name = strings.TrimSuffix(name, filepath.Ext(name))
	}
	return name
}
