package net

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/sirupsen/logrus"

	"github.com/akshaybabloo/binstall/pkg"

	"github.com/go-resty/resty/v2"
	"github.com/google/go-github/v68/github"
	"github.com/hashicorp/go-version"
	"golift.io/xtractr"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/utils"
)

// ===============================================================================
// ==============================  CHECK UPDATES  ================================
// ===============================================================================

const (
	GitHub = iota + 1
	Others
)

var ignoreFileExt = []string{".deb", ".sig", ".rpm", ".pem", ".sbom"}
var allowedMediaTypes = []string{"application/gzip", "application/zip", "application/x-bzip1-compressed-tar", "application/x-bzip-compressed-tar", "raw", "application/x-gtar", "application/octet-stream"}

func getCurrentVersion(b models.Binaries) (models.Binaries, error) {
	for i := range b.Files {
		file := &b.Files[i]
		if file.CheckVersion {
			cmd := exec.Command(file.FileName, file.VersionCommand.Args)
			stdout, err := cmd.Output()
			if err != nil {
				if errors.Is(err, exec.ErrNotFound) {
					return models.Binaries{}, exec.ErrNotFound
				}
				return models.Binaries{}, fmt.Errorf("failed to get the current version for: %s - %s", file.FileName, err.Error())
			}
			ver, err := utils.ExtractVersion(string(stdout), file.VersionCommand.RegexVersion)
			if err != nil {
				return models.Binaries{}, fmt.Errorf("failed to compile the regex for: %s - %s", file.FileName, err.Error())
			}
			b.CurrentVersion = ver
		}
	}
	return b, nil
}

func findProvider(b models.Binaries) models.Binaries {
	if strings.Contains(b.URL, "github.com") {
		b.Provider = GitHub
	} else {
		b.Provider = Others
	}
	return b
}

func checkForNewVersion(b models.Binaries, a ...string) (models.Binaries, error) {
	if b.Provider == GitHub {
		info := utils.ExpandGitHubURL(b.URL)
		var c *github.Client

		if len(a) > 0 && a[0] != "" {
			b.Token = a[0]
			c = github.NewClient(nil).WithAuthToken(b.Token)
		} else {
			c = github.NewClient(nil)
		}

		releases, _, err := c.Repositories.GetLatestRelease(context.Background(), info.Owner, info.Repo)
		if err != nil {
			return models.Binaries{}, err
		}

		for _, asset := range releases.Assets {
			osArch := utils.FigureOutOSAndArch(asset.GetName())
			ext := filepath.Ext(asset.GetName())
			if runtime.GOOS == osArch.OS && runtime.GOARCH == osArch.Arch && !utils.Contains(ignoreFileExt, ext) {
				b.DownloadURL = asset.GetBrowserDownloadURL()
				b.NewVersion = releases.GetTagName()
				b.DownloadFileName = asset.GetName()
				b.ContentType = asset.GetContentType()
				b.OsInfo = osArch
				break
			}
		}
	}
	if b.DownloadURL == "" {
		return models.Binaries{}, pkg.ErrNetBinaryNotFound
	}
	return b, nil
}

// CheckUpdates Does four things:
//
// 1. Get the current version of the binary
// 2. Find the provider of the binary
// 3. Check for the new version of the binary
// 4. Compare the current version with the new version
func CheckUpdates(b models.Binaries, a ...string) (models.Binaries, error) {
	_version, err := getCurrentVersion(b)
	if err != nil {
		// If not found, install the binary
		if errors.Is(err, exec.ErrNotFound) {
			pr := findProvider(b)
			checkV, err := checkForNewVersion(pr, a...)
			if err != nil {
				if errors.Is(err, pkg.ErrNetBinaryNotFound) {
					logrus.Debugf("No binary found for the current OS and Arch: %s\n", b.Name)
					return models.Binaries{}, nil
				}
				return models.Binaries{}, err
			}

			b = checkV
			b.CurrentVersion = "Not Found"
			b.UpdatesAvailable = true

			return b, nil
		}
		return models.Binaries{}, err
	}

	pr := findProvider(_version)
	checkV, err := checkForNewVersion(pr, a...)
	if err != nil {
		if errors.Is(err, pkg.ErrNetBinaryNotFound) {
			logrus.Debugf("No binary found for the current OS and Arch: %s\n", b.Name)
			return models.Binaries{}, nil
		}
		return models.Binaries{}, fmt.Errorf("error checking for new version for: %s - %s", b.Name, err.Error())
	}
	if checkV.CurrentVersion == "" {
		checkV.CurrentVersion = "0.0.0"
	}

	currentVersion, err := version.NewVersion(checkV.CurrentVersion)
	if err != nil {
		return models.Binaries{}, fmt.Errorf("error parsing the current version for: %s - %w ", b.Name, err)
	}

	newVersion, err := version.NewVersion(checkV.NewVersion)
	if err != nil {
		return models.Binaries{}, fmt.Errorf("error parsing the new version for: %s - %w ", b.Name, err)
	}

	if currentVersion.LessThan(newVersion) {
		checkV.UpdatesAvailable = true
	} else {
		checkV.UpdatesAvailable = false
	}

	return checkV, nil
}

// ===============================================================================
// =========================  DOWNLOAD AND MOVE FILES  ===========================
// ===============================================================================

func downloadFile(b models.Binaries) (models.Binaries, error) {

	b.DownloadFolder = filepath.Join(os.TempDir(), b.Name)
	b.DownloadFilePath = filepath.Join(b.DownloadFolder, b.DownloadFileName)

	client := resty.New()
	_, err := client.R().SetOutput(b.DownloadFilePath).Get(b.DownloadURL)
	if err != nil {
		return models.Binaries{}, fmt.Errorf("failed to download the file for: %s - %s", b.Name, err.Error())
	}
	return b, nil
}

func verifyFile(b models.Binaries) (bool, error) {
	// First check inline checksum
	if b.Sha.Checksum != "" {
		shaType := b.Sha.ShaType
		if shaType == "" {
			shaType = "sha256"
		}
		if shaType == "sha256" {
			calculated, err := utils.CalculateSHA256(b.DownloadFilePath)
			if err != nil {
				return false, fmt.Errorf("failed to calculate sha256 for %s: %w", b.Name, err)
			}
			expected := strings.ToLower(strings.TrimSpace(b.Sha.Checksum))
			if strings.ToLower(calculated) != expected {
				return false, fmt.Errorf("checksum mismatch for %s: expected %s, got %s", b.Name, expected, calculated)
			}
			return true, nil
		}
	}

	// Then check URL-based checksum
	if b.Sha.URL != "" {
		client := resty.New()
		r, err := client.R().Get(b.Sha.URL)
		if err != nil {
			return false, fmt.Errorf("failed to get checksum file for %s: %w", b.Name, err)
		}

		shaContent := string(r.Body())

		if b.Sha.ShaType == "" {
			return false, fmt.Errorf("no sha type provided for: %s", b.Name)
		}

		if b.Sha.ShaType == "sha256" {
			calculated, err := utils.CalculateSHA256(b.DownloadFilePath)
			if err != nil {
				return false, fmt.Errorf("failed to calculate sha256 for %s: %w", b.Name, err)
			}

			// Parse the SHA file to extract the checksum
			expected := utils.ParseSHAFile(shaContent, b.DownloadFileName)
			if expected == "" {
				return false, fmt.Errorf("could not parse checksum from SHA file for %s", b.Name)
			}

			if strings.ToLower(calculated) != expected {
				return false, fmt.Errorf("checksum mismatch for %s: expected %s, got %s", b.Name, expected, calculated)
			}
			return true, nil
		}
	}

	// No checksum verification configured - pass
	return true, nil
}

func uncompressFile(b models.Binaries) error {
	if b.DownloadFileName == "" {
		return fmt.Errorf("no file to uncompress for: %s", b.Name)
	}

	mtype, err := mimetype.DetectFile(b.DownloadFilePath)
	if err != nil {
		return fmt.Errorf("failed to detect the file type for: %s - %s", b.Name, err.Error())
	}
	logrus.Debugf("File type: %s, Extension: %s\n", mtype.String(), mtype.Extension())

	if mtype.String() == "application/x-executable" {
		return nil
	}

	mediaType, _, err := mime.ParseMediaType(b.ContentType)
	if err != nil {
		return err
	}
	// Check if the file is a gzip or zip file, if not return nil
	if !utils.Contains(allowedMediaTypes, mediaType) {
		return fmt.Errorf("file type not supported: %s. Allowed types: %v", mediaType, allowedMediaTypes)
	}

	x := &xtractr.XFile{
		FilePath:  b.DownloadFilePath,
		OutputDir: b.DownloadFolder,
		FileMode:  0755,
		DirMode:   0755,
	}
	o1, o2, o3, err := xtractr.ExtractFile(x)
	if err != nil {
		return fmt.Errorf("failed to uncompress the file for: %s - %s", b.Name, err.Error())
	}
	logrus.Debugf("Size %d, %v files, %v files\n", o1, o2, o3)
	return nil
}

func moveFiles(b *models.Binaries) error {
	// Expand the ~ to the home directory
	if strings.HasPrefix(b.InstallLocation, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory for install location: %w", err)
		}
		b.InstallLocation = filepath.Join(homeDir, b.InstallLocation[2:])
	}

	// Ensure the installation location exists
	err := os.MkdirAll(b.InstallLocation, 0755)
	if err != nil {
		return fmt.Errorf("failed to create install directory %s: %w", b.InstallLocation, err)
	}

	for _, file := range b.Files {
		srcPath := filepath.Join(b.DownloadFolder, file.FileName)
		if file.SourcePath != "" {
			srcPath = filepath.Join(b.DownloadFolder, file.SourcePath)
		}
		dstPath := filepath.Join(b.InstallLocation, file.FileName)
		if file.RenameTo != "" {
			dstPath = filepath.Join(b.InstallLocation, file.RenameTo)
		}

		// Check version before move
		var cmd *exec.Cmd
		var stdout []byte
		if file.ExecuteWhenCopying {

			if file.CheckVersion || !file.CopyIt {
				cmd = exec.Command(srcPath, file.VersionCommand.Args)
				stdout, err := cmd.CombinedOutput()
				if err != nil {
					return fmt.Errorf("failed to execute %s before move: %w\nOutput: %s", file.FileName, err, stdout)
				}
			}

			// Check if source file exists
			if _, err := os.Stat(srcPath); os.IsNotExist(err) {
				return fmt.Errorf("source file does not exist: %s", srcPath)
			}

			// Remove the destination file if it exists
			err = os.Remove(dstPath)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove existing file %s: %w", dstPath, err)
			}
		}

		if file.CopyIt {
			logrus.Debugf("Copying %s to %s\n", srcPath, dstPath)
			// Move the file
			err = os.Rename(srcPath, dstPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// Try to adjust the path - archives often extract to a versioned subdirectory
					f := utils.FileNameWithoutExtension(b.DownloadFileName)
					// Use sourcePath if available, otherwise just the fileName
					relativePath := file.FileName
					if file.SourcePath != "" {
						relativePath = file.SourcePath
					}
					srcPath = filepath.Join(b.DownloadFolder, f, relativePath)
					err = os.Rename(srcPath, dstPath)
					if err != nil {
						return fmt.Errorf("file not found even after path adjustment: %s to %s: %w", srcPath, dstPath, err)
					}
				} else {
					return fmt.Errorf("failed to move file from %s to %s: %w", srcPath, dstPath, err)
				}
			}

			// Verify the file was moved
			if _, err := os.Stat(dstPath); os.IsNotExist(err) {
				return fmt.Errorf("file was not successfully moved to %s", dstPath)
			}

			// Set execute permissions if needed
			err = os.Chmod(dstPath, 0755)
			if err != nil {
				return fmt.Errorf("failed to set execute permissions on %s: %w", dstPath, err)
			}

			// Verify permissions
			_, err = os.Stat(dstPath)
			if err != nil {
				return fmt.Errorf("failed to get file info for %s: %w", dstPath, err)
			}

			if file.CheckVersion {
				// Check version after move
				cmd = exec.Command(dstPath, file.VersionCommand.Args)
				stdout, err = cmd.CombinedOutput()
				if err != nil {
					return fmt.Errorf("failed to execute %s after move: %w\nOutput: %s", file.FileName, err, stdout)
				}
			}
		}
	}

	return nil
}

func verifyNewBin(b models.Binaries) error {
	for _, file := range b.Files {
		if !file.CheckVersion {
			continue
		}

		fullPath := filepath.Join(b.InstallLocation, file.FileName)

		// Check if the binary exists at the expected location
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			return fmt.Errorf("binary not found at expected location: %s", fullPath)
		}

		// Find the actual path of the binary that will be executed
		actualPath, err := exec.LookPath(file.FileName)
		if err != nil {
			return fmt.Errorf("failed to find %s in PATH: %w", file.FileName, err)
		}

		// Check if the actual path matches the expected path
		if actualPath != fullPath {
			logrus.Debugf("Binary path mismatch: Actual path: %s, Expected path: %s", actualPath, fullPath)
		}

		// Execute the binary using the full path
		cmd := exec.Command(fullPath, file.VersionCommand.Args)
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute %s: %w\nOutput: %s", fullPath, err, stdout)
		}

		match, err := utils.ExtractVersion(string(stdout), file.VersionCommand.RegexVersion)
		if err != nil {
			return fmt.Errorf("failed to compile regex for %s: %w", file.FileName, err)
		}

		installedVersion, err := version.NewVersion(strings.TrimSpace(match))
		if err != nil {
			return fmt.Errorf("failed to parse installed version for %s: %w", file.FileName, err)
		}

		newVersion, err := version.NewVersion(strings.TrimSpace(b.NewVersion))
		if err != nil {
			return fmt.Errorf("failed to parse new version for %s: %w", file.FileName, err)
		}

		if !installedVersion.Equal(newVersion) {
			return fmt.Errorf("version mismatch for %s. Installed: %s, Expected: %s",
				file.FileName, installedVersion.String(), newVersion.String())
		}
	}
	return nil
}

// DownloadAndMoveFiles Does five things:
//
// 1. Download the file
// 2. Verify the file
// 3. Uncompress the file
// 4. Move the files to the install location
// 5. Verify the new binary
func DownloadAndMoveFiles(b models.Binaries) error {
	dl, err := downloadFile(b)
	if err != nil {
		return err
	}

	file, err := verifyFile(dl)
	if err != nil && !file {
		return err
	}

	err = uncompressFile(dl)
	if err != nil {
		return err
	}

	err = moveFiles(&dl)
	if err != nil {
		return err
	}

	err = verifyNewBin(dl)
	if err != nil {
		return err
	}

	return nil
}
