package download

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/akshaybabloo/binstall/pkg/fileio"

	"github.com/MakeNowJust/heredoc"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"

	"github.com/akshaybabloo/binstall/models"
	"github.com/akshaybabloo/binstall/pkg/net"
)

var isCheckOnly bool
var nqa bool
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
			for binary, err := range data {
				if err != nil {
					return err
				}

				if binary.Ignore {
					continue
				}

				if len(includeBinaries) > 0 && slices.Contains(excludeBinaries, binary.Name) {
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

			if len(binUpdates) == 0 {
				s.Stop()
				fmt.Println(color.GreenString("No updates available"))
				return nil
			}
			s.FinalMSG = color.GreenString("Updates found\n")
			s.Stop()

			t := table.NewWriter()
			t.SetOutputMirror(os.Stdout)
			t.AppendHeader(table.Row{"Name", "Current Version", "New Version"})
			for _, update := range binUpdates {
				t.AppendRow([]any{update.Name, update.CurrentVersion, update.NewVersion})
			}
			t.SetStyle(table.StyleLight)
			t.Render()

			if isCheckOnly {
				return nil
			}

			if !nqa {
				fmt.Print("Do you want to update? (y/n): ")
				var input string
				_, err := fmt.Scanln(&input)
				if err != nil {
					return err
				}
				if input != "y" {
					return nil
				}
			}

			s = spinner.New(spinner.CharSets[11], 100*time.Millisecond)
			s.Suffix = color.GreenString(" Installing updates...")
			s.Start()

			var errs []error

			for _, update := range binUpdates {
				s.Suffix = color.GreenString(fmt.Sprintf(" Installing %s...", update.Name))
				err = net.DownloadAndMoveFiles(update)
				if err != nil {
					errs = append(errs, fmt.Errorf("failed to update %s:\n%w", update.Name, err))
					continue
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
	downloadCmd.Flags().StringVarP(&token, "token", "t", "", "GitHub token")
	downloadCmd.Flags().StringSliceVarP(&excludeBinaries, "exclude", "e", []string{}, "Exclude binaries from update")
	downloadCmd.Flags().StringSliceVarP(&includeBinaries, "include", "i", []string{}, "Include only specified binaries in update")

	return downloadCmd
}
