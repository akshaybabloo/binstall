package upgrade

import (
	"github.com/spf13/cobra"
)

func NewUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrades to the latest version of binstall",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find executable path

			return nil
		},
	}
}
