// Package cmd provides the command line interface for binstall.
package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/akshaybabloo/binstall/cmd/download"
	"github.com/akshaybabloo/binstall/cmd/schema"
	"github.com/spf13/cobra"
)

var verbose bool

// NewRootCmd creates the root command for the binstall application,
// sets up the version template, adds subcommands, and configures
// persistent flags such as the verbose flag.
func NewRootCmd(appVersion, buildDate string) *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "binstall [OPTIONS] [COMMANDS]",
		Short: "binstall is a tool to download and install binaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				level, err := logrus.ParseLevel("debug")
				if err != nil {
					return err
				}
				logrus.SetLevel(level)
			}
			return nil
		},
	}

	rootCmd.AddCommand(download.NewDownloadCmd())
	rootCmd.AddCommand(schema.NewSchemaCmd())

	formattedVersion := format(appVersion, buildDate)
	rootCmd.SetVersionTemplate(formattedVersion)
	rootCmd.Version = formattedVersion

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "verbose output")

	return rootCmd
}

func format(version, buildDate string) string {
	return fmt.Sprintf("binstall %s %s\n", version, buildDate)
}
