package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/akshaybabloo/binstall/cmd/download"
	"github.com/akshaybabloo/binstall/cmd/schema"
	"github.com/spf13/cobra"
)

var verbose bool

// NewRootCmd root command
func NewRootCmd(appVersion, buildDate string) *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "binstall [OPTIONS] [COMMANDS]",
		Short: "binstall is a tool to download and install binaries",
	}

	rootCmd.AddCommand(download.NewDownloadCmd())
	rootCmd.AddCommand(schema.NewSchemaCmd())

	formattedVersion := format(appVersion, buildDate)
	rootCmd.SetVersionTemplate(formattedVersion)
	rootCmd.Version = formattedVersion

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")

	if verbose {
		level, err := logrus.ParseLevel("debug")
		if err != nil {
			return nil
		}
		logrus.SetLevel(level)
	}

	return rootCmd
}

func format(version, buildDate string) string {
	return fmt.Sprintf("binstall %s %s\n", version, buildDate)
}
