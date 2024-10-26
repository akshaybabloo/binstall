package net

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/akshaybabloo/binstall/pkg"
	"github.com/sirupsen/logrus"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/utils"
	"github.com/go-resty/resty/v2"
	"github.com/google/go-github/v66/github"
	"github.com/hashicorp/go-version"
	"golift.io/xtractr"
)

//===============================================================================
//==============================  CHECK UPDATES  ================================
//===============================================================================

const (
	GitHub = iota + 1
	Others
)

var ignoreFileExt = []string{".deb", ".sig", ".rpm", ".pem", ".sbom"}
var allowedMediaTypes = []string{"application/gzip", "application/zip", "application/x-bzip-compressed-tar", "raw", "application/x-gtar"}

func getCurrentVersion(b models.Binaries) (models.Binaries, error) {
	for i := range b.Files {
		file := &b.Files[i]
		if file.Execute {
			cmd := exec.Command(file.FileName, file.VersionCommand.Args)
			stdout, err := cmd.Output()
			if err != nil {
				if errors.Is(err, exec.ErrNotFound) {
					return models.Binaries{}, exec.ErrNotFound
				}
				return models.Binaries{}, errors.New("failed to get the current version: " + err.Error())
			}
			r, err := regexp.Compile(file.VersionCommand.RegexVersion)
			if err != nil {
				return models.Binaries{}, errors.New("failed to compile the regex: " + err.Error())
			}
			if r.MatchString(string(stdout)) {
				matched := r.FindString(string(stdout))
				b.CurrentVersion = matched
			}
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

func checkForNewVersion(b models.Binaries) (models.Binaries, error) {
	if b.Provider == GitHub {
		info := utils.ExpandGitHubURL(b.URL)

		c := github.NewClient(nil)
		releases, _, err := c.Repositories.GetLatestRelease(context.Background(), info.Owner, info.Repo)
		if err != nil {
			return models.Binaries{}, nil
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
func CheckUpdates(b models.Binaries) (models.Binaries, error) {
	_version, err := getCurrentVersion(b)
	if err != nil {
		// If not found, install the binary
		if errors.Is(err, exec.ErrNotFound) {
			pr := findProvider(b)
			checkV, err := checkForNewVersion(pr)
			if err != nil {
				if errors.Is(err, pkg.ErrNetBinaryNotFound) {
					logrus.Debugf("No binary found for the current OS and Arch %s\n", b.Name)
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
	checkV, err := checkForNewVersion(pr)
	if err != nil {
		if errors.Is(err, pkg.ErrNetBinaryNotFound) {
			logrus.Debugf("No binary found for the current OS and Arch %s\n", b.Name)
			return models.Binaries{}, nil
		}
		return models.Binaries{}, errors.New("error checking for new version: " + err.Error())
	}
	if checkV.CurrentVersion == "" {
		checkV.CurrentVersion = "0.0.0"
	}

	currentVersion, err := version.NewVersion(checkV.CurrentVersion)
	if err != nil {
		return models.Binaries{}, fmt.Errorf("error parsing the current version for %s: %w ", b.Name, err)
	}

	newVersion, err := version.NewVersion(checkV.NewVersion)
	if err != nil {
		return models.Binaries{}, fmt.Errorf("error parsing the new version for %s: %w ", b.Name, err)
	}

	if currentVersion.LessThan(newVersion) {
		checkV.UpdatesAvailable = true
	} else {
		checkV.UpdatesAvailable = false
	}

	return checkV, nil
}

//===============================================================================
//=========================  DOWNLOAD AND MOVE FILES  ===========================
//===============================================================================

func downloadFile(b models.Binaries) (models.Binaries, error) {

	b.DownloadFolder = filepath.Join(os.TempDir(), b.Name)
	b.DownloadFilePath = filepath.Join(b.DownloadFolder, b.DownloadFileName)

	client := resty.New()
	_, err := client.R().SetOutput(filepath.Join(b.DownloadFilePath)).Get(b.DownloadURL)
	if err != nil {
		return models.Binaries{}, errors.New("failed to download the file: " + err.Error())
	}
	return b, nil
}

// TODO: Implement this function
func verifyFile(b models.Binaries) (bool, error) {
	if b.Sha.URL != "" {
		client := resty.New()
		r, err := client.R().Get(b.Sha.URL)
		if err != nil {
			return false, errors.New("failed to get the checksum file: " + err.Error())
		}

		shaStr := string(r.Body())

		if b.Sha.ShaType == "" {
			return false, errors.New("no sha type provided")
		} else if b.Sha.ShaType == "sha256" {
			sha256, err := utils.CalculateSHA256(b.DownloadFilePath)
			if err != nil {
				return false, errors.New("failed to calculate the sha256: " + err.Error())
			}
			if sha256 != shaStr {
				return false, errors.New("checksums do not match")
			}
		}
	}
	// Skip the checksum verification
	return true, nil
}

func uncompressFile(b models.Binaries) error {
	if b.DownloadFileName == "" {
		return errors.New("no file to uncompress")
	}

	mediaType, _, err := mime.ParseMediaType(b.ContentType)
	if err != nil {
		return err
	}
	// Check if the file is a gzip or zip file, if not return nil
	if !utils.Contains(allowedMediaTypes, mediaType) {
		return nil
	}

	x := &xtractr.XFile{
		FilePath:  b.DownloadFilePath,
		OutputDir: b.DownloadFolder,
	}
	o1, o2, o3, err := xtractr.ExtractFile(x)
	if err != nil {
		return errors.New("failed to uncompress the file: " + err.Error())
	}
	logrus.Debugf("Size %d, %v files, %v files\n", o1, o2, o3)
	return nil
}

func moveFiles(b *models.Binaries, path ...string) error {
	// Expand the ~ to the home directory
	if strings.HasPrefix(b.InstallLocation, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get user home directory: %w", err)
		}
		b.InstallLocation = filepath.Join(homeDir, b.InstallLocation[2:])
	}

	// Ensure the installation location exists
	err := os.MkdirAll(b.InstallLocation, 0755)
	if err != nil {
		return fmt.Errorf("failed to create install directory: %w", err)
	}

	for _, file := range b.Files {
		srcPath := filepath.Join(b.DownloadFolder, file.FileName)
		dstPath := filepath.Join(b.InstallLocation, file.FileName)
		if file.RenameTo != "" {
			dstPath = filepath.Join(b.InstallLocation, file.RenameTo)
		}

		// Check version before move
		var cmd *exec.Cmd
		var stdout []byte
		if file.ExecuteWhenCopying {

			if file.Execute || !file.CopyIt {
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
			// Move the file
			err = os.Rename(srcPath, dstPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					// Try to adjust the path, this seems to happen with xz files
					p := strings.Split(srcPath, "/")
					f := utils.FileNameWithoutExtension(b.DownloadFileName)
					srcPath = filepath.Join(b.DownloadFolder, f, p[len(p)-1])
					err = os.Rename(srcPath, dstPath)
					if err != nil {
						return fmt.Errorf("file not found even after path adjustment: %w", err)
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

			if file.Execute {
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
		if !file.Execute {
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
			logrus.Debugf("Actual path: %s, Expected path: %s", actualPath, fullPath)
		}

		// Execute the binary using the full path
		cmd := exec.Command(fullPath, file.VersionCommand.Args)
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to execute %s: %w\nOutput: %s", fullPath, err, stdout)
		}

		r, err := regexp.Compile(file.VersionCommand.RegexVersion)
		if err != nil {
			return fmt.Errorf("failed to compile regex for %s: %w", file.FileName, err)
		}

		match := r.FindString(string(stdout))
		if match == "" {
			return fmt.Errorf("version not found in output for %s. Output: %s", file.FileName, stdout)
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
