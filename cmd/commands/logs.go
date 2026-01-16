package commands

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View audit logs and reports",
	Long: `View audit logs, reports, and session information.

Examples:
  drystone logs list              # List all audit sessions
  drystone logs show <session>    # Show session details
  drystone logs open <session>    # Open session report
`,
}

var logsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List audit sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		auditLogsDir := "./audit-logs"

		entries, err := ioutil.ReadDir(auditLogsDir)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No audit sessions found")
				return nil
			}
			return fmt.Errorf("failed to read audit logs: %w", err)
		}

		if len(entries) == 0 {
			fmt.Println("No audit sessions found")
			return nil
		}

		fmt.Println("\n📋 Audit Sessions:\n")
		for _, entry := range entries {
			if entry.IsDir() {
				fmt.Printf("  📁 %s\n", entry.Name())
			}
		}
		fmt.Println()

		return nil
	},
}

var logsShowCmd = &cobra.Command{
	Use:   "show <session>",
	Short: "Show session details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionID := args[0]
		sessionPath := filepath.Join("./audit-logs", sessionID)

		// Check if session exists
		if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
			return fmt.Errorf("session not found: %s", sessionID)
		}

		fmt.Printf("\n📁 Session: %s\n\n", sessionID)

		// List contents
		entries, _ := ioutil.ReadDir(sessionPath)
		for _, entry := range entries {
			if entry.IsDir() {
				fmt.Printf("  📁 %s/\n", entry.Name())
			} else {
				fmt.Printf("  📄 %s\n", entry.Name())
			}
		}
		fmt.Println()

		return nil
	},
}

var logsOpenCmd = &cobra.Command{
	Use:   "open <session>",
	Short: "Open session report",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionID := args[0]
		reportPath := filepath.Join("./audit-logs", sessionID, "reports", "report.md")

		if _, err := os.Stat(reportPath); os.IsNotExist(err) {
			return fmt.Errorf("report not found: %s", reportPath)
		}

		fmt.Printf("Opening report: %s\n", reportPath)
		// In a real implementation, open with default editor or viewer

		return nil
	},
}

func init() {
	logsCmd.AddCommand(logsListCmd)
	logsCmd.AddCommand(logsShowCmd)
	logsCmd.AddCommand(logsOpenCmd)
}
