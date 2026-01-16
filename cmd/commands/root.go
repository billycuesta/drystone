package commands

import (
	"os"

	"github.com/spf13/cobra"
)

// RootCmd represents the root command
var RootCmd = &cobra.Command{
	Use:   "drystone",
	Short: "AWS Security Audit CLI powered by Claude",
	Long: `Drystone - AWS Security Audit CLI powered by Claude

Automated AWS security auditing with modular skills:
- IAM Security Audit
- Internet Exposure Scanning
- Network Policies Analysis
- Vulnerability Detection

Example:
  drystone audit --skill iam --profile production
  drystone audit                    # Interactive mode
`,
	Version: "0.1.0-alpha",
}

// Execute runs the root command
func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Global flags
	RootCmd.PersistentFlags().String("profile", "default", "AWS profile to use")
	RootCmd.PersistentFlags().String("region", "us-east-1", "AWS region")
	RootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode")

	// Add subcommands
	RootCmd.AddCommand(auditCmd)
	RootCmd.AddCommand(skillCmd)
	RootCmd.AddCommand(logsCmd)
	RootCmd.AddCommand(versionCmd)
}
