package download

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/akshaybabloo/binstall/pkg/fileio"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/net"
)

var isCheckOnly bool
var nqa bool
var dryRun bool
var parallelCount int
var token string
var excludeBinaries []string
var includeBinaries []string

// NewDownloadCmd command function to downloads required binaries
func NewDownloadCmd() *cobra.Command {
	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "Download required binaries",
		Example: heredoc.Doc(`
			To check and download all the required binaries
			$ binstall download <config files folder>

			To only check for updates
			$ binstall download <config files folder> --check

			To update without asking
			$ binstall download <config files folder> --nqa`),
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) == 0 {
				return errors.New("no config files folder provided")
			}

			s := spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = color.GreenString(" Checking for updates...")
			s.Start()

			stat, err := os.Stat(args[0])
			if err != nil {
				return err
			}
			if !stat.IsDir() {
				return errors.New("provided path is not a directory")
			}

			data, err := fileio.ReadYamlFiles(filepath.FromSlash(args[0]))
			if err != nil {
				return err
			}

			var bins []models.Binaries
			var pendingRemovals []models.Binaries
			for binary, err := range data {
				if err != nil {
					return err
				}

				if binary.Ignore {
					continue
				}

				if binary.Settings != nil && !binary.Settings.Active {
					if binary.Settings.DeleteIfNotActive {
						// Deferred: removing a deb/rpm needs root, and asking
						// for a password under a running spinner would hide
						// the prompt.
						pendingRemovals = append(pendingRemovals, binary)
					}
					continue
				}

				if len(excludeBinaries) > 0 && slices.Contains(excludeBinaries, binary.Name) {
					continue
				}

				if len(includeBinaries) > 0 && !slices.Contains(includeBinaries, binary.Name) {
					continue
				}

				if token == "" && os.Getenv("GITHUB_TOKEN") != "" {
					token = os.Getenv("GITHUB_TOKEN")
				}

				updates, err := net.CheckUpdates(binary, token)
				if err != nil {
					return err
				}

				bins = append(bins, updates)
			}

			var binUpdates []models.Binaries
			for _, bin := range bins {
				if bin.UpdatesAvailable {
					binUpdates = append(binUpdates, bin)
				}
			}

			s.Stop()

			// --check and --dry-run must not change anything, so inactive
			// configs are only reported, not uninstalled.
			if isCheckOnly || dryRun {
				reportRemovals(pendingRemovals)
			} else if err := removeInactive(pendingRemovals); err != nil {
				return err
			}

			if len(binUpdates) == 0 {
				fmt.Println(color.GreenString("No updates available"))
				return nil
			}
			fmt.Print(color.GreenString("Updates found\n"))

			t := table.NewWriter()
			t.SetOutputMirror(os.Stdout)
			t.AppendHeader(table.Row{"Name", "Current Version", "New Version"})
			for _, update := range binUpdates {
				t.AppendRow([]any{update.Name, update.CurrentVersion, update.NewVersion})
			}
			t.SetStyle(table.StyleLight)
			t.Render()

			if isCheckOnly || dryRun {
				if dryRun {
					fmt.Println("\n--- Dry Run Summary ---")
					for _, update := range binUpdates {
						fmt.Printf("\nBinary: %s\n", update.Name)
						fmt.Printf("  Current Version: %s\n", update.CurrentVersion)
						fmt.Printf("  New Version: %s\n", update.NewVersion)
						fmt.Printf("  Download URL: %s\n", update.DownloadURL)
						if update.IsPackageInstall() {
							manager := net.PackageManagerName(update)
							if manager == "" {
								manager = color.RedString("no package manager available on this host")
							}
							fmt.Printf("  Install Method: %s package via %s (requires root)\n", update.ResolvedType(), manager)
							continue
						}
						fmt.Printf("  Install Location: %s\n", update.InstallLocation)
						fmt.Printf("  Files:\n")
						for _, file := range update.Files {
							if file.CopyIt {
								destName := file.FileName
								if file.RenameTo != "" {
									destName = file.RenameTo
								}
								srcName := file.FileName
								if file.SourcePath != "" {
									srcName = file.SourcePath
								}
								fmt.Printf("    - %s -> %s\n", srcName, destName)
							}
						}
					}
				}
				return nil
			}

			if !nqa {
				fmt.Print("Do you want to update? (Y/n): ")
				var input string
				_, err := fmt.Scanln(&input)
				if err != nil {
					input = ""
				}
				if input != "" && (input == "no" || input == "n" || input == "N") {
					return nil
				}
			}

			// Package installs need root. Acquire it here, while the terminal
			// is still free, so the workers below never compete for a password
			// prompt behind the spinner.
			if slices.ContainsFunc(binUpdates, net.NeedsRoot) {
				if err := net.PrepareElevation(); err != nil {
					return err
				}
			}

			s = spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = color.GreenString(" Installing updates...")
			s.Start()

			// Result type for download operations
			type downloadResult struct {
				name string
				err  error
			}

			resultCh := make(chan downloadResult, len(binUpdates))
			workCh := make(chan models.Binaries, len(binUpdates))

			// Determine number of workers
			numWorkers := parallelCount
			if numWorkers < 1 {
				numWorkers = 1
			}
			if numWorkers > len(binUpdates) {
				numWorkers = len(binUpdates)
			}

			// Start workers
			var wg sync.WaitGroup
			for i := 0; i < numWorkers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for update := range workCh {
						err := net.DownloadAndMoveFiles(update)
						resultCh <- downloadResult{name: update.Name, err: err}
					}
				}()
			}

			// Send work
			for _, update := range binUpdates {
				workCh <- update
			}
			close(workCh)

			// Wait for completion in a goroutine
			go func() {
				wg.Wait()
				close(resultCh)
			}()

			// Collect results
			var errs []error
			completed := 0
			for result := range resultCh {
				completed++
				s.Suffix = color.GreenString(fmt.Sprintf(" Installing updates... (%d/%d)", completed, len(binUpdates)))
				if result.err != nil {
					errs = append(errs, fmt.Errorf("failed to update %s:\n%w", result.name, result.err))
				}
			}

			// Stop the spinner and check for errors
			if len(errs) > 0 {
				s.Stop()
				fmt.Println(color.RedString("Some updates failed to install:"))
				for _, err := range errs {
					fmt.Println(color.RedString(err.Error()))
				}
				return nil
			}

			s.FinalMSG = color.GreenString("Updates installed\n")
			s.Stop()

			return nil
		},
	}

	downloadCmd.Flags().BoolVar(&isCheckOnly, "check", false, "Check for updates")
	downloadCmd.Flags().BoolVar(&nqa, "nqa", false, "Update without asking")
	downloadCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be installed without making changes")
	downloadCmd.Flags().IntVarP(&parallelCount, "parallel", "p", 4, "Number of parallel downloads")
	downloadCmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token")
	downloadCmd.Flags().StringSliceVarP(&excludeBinaries, "exclude", "e", []string{}, "Exclude binaries from update")
	downloadCmd.Flags().StringSliceVarP(&includeBinaries, "include", "i", []string{}, "Include only specified binaries in update")

	return downloadCmd
}

// removeInactive uninstalls configs that are marked inactive with
// settings.deleteIfNotActive.
//
// Every package name is resolved before root is acquired. That keeps a
// misconfigured entry from failing only after the user has typed a password,
// and means a run whose packages are already gone never prompts at all. Root
// is then acquired once, so removing several packages asks at most once.
func removeInactive(bins []models.Binaries) error {
	if len(bins) == 0 {
		return nil
	}

	needsRoot := false
	for _, b := range bins {
		if !net.NeedsRootForRemoval(b) {
			continue
		}
		name, err := net.PackageToRemove(b)
		if err != nil {
			return err
		}
		// An empty name means the package is not installed, so removing it
		// needs no privileges.
		if name != "" {
			needsRoot = true
		}
	}

	if needsRoot {
		if err := net.PrepareElevation(); err != nil {
			return err
		}
	}

	for _, b := range bins {
		if err := net.RemoveInstalledFiles(b); err != nil {
			return err
		}
	}
	return nil
}

// reportRemovals prints what an inactive config would uninstall, for --check
// and --dry-run.
func reportRemovals(bins []models.Binaries) {
	for _, b := range bins {
		if t := net.ResolvedInstallType(b); t.IsPackage() {
			// A package config with install: false never installed anything,
			// so there is nothing to report removing.
			if !net.NeedsRootForRemoval(b) {
				fmt.Printf("%s %s is inactive: nothing to remove (%s with install: false)\n",
					color.YellowString("!"), b.Name, t)
				continue
			}

			name, err := net.PackageToRemove(b)
			switch {
			case err != nil:
				name = color.RedString(err.Error())
			case name == "":
				name = "nothing (not installed)"
			}
			fmt.Printf("%s %s is inactive: would uninstall %s package %s\n",
				color.YellowString("!"), b.Name, t, name)
			continue
		}
		fmt.Printf("%s %s is inactive: would remove installed files from %s\n",
			color.YellowString("!"), b.Name, b.InstallLocation)
	}
}
