package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Drystone v0.1.0-alpha")
		fmt.Println("AWS Security Audit CLI powered by Claude")
	},
}
