package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var skillCmd = &cobra.Command{
	Use:   "skill",
	Short: "List and manage skills",
	Long: `Manage Drystone security audit skills.

Examples:
  drystone skill list           # List available skills
  drystone skill info iam       # Show skill details
`,
}

var skillListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available skills",
	RunE: func(cmd *cobra.Command, args []string) error {
		skills := []struct {
			name        string
			description string
		}{
			{"iam", "AWS IAM Security Audit"},
			{"exposure", "Internet Exposure Scanning (Phase 2)"},
			{"network", "Network Policies Analysis (Phase 2)"},
			{"vulns", "Vulnerability Detection (Phase 3)"},
		}

		fmt.Println("\n📋 Available Skills:\n")
		for _, skill := range skills {
			if skill.name == "iam" {
				fmt.Printf("  ✅ %s\n", skill.name)
				fmt.Printf("     %s\n\n", skill.description)
			} else {
				fmt.Printf("  ⏳ %s (planned)\n", skill.name)
				fmt.Printf("     %s\n\n", skill.description)
			}
		}

		return nil
	},
}

var skillInfoCmd = &cobra.Command{
	Use:   "info <skill>",
	Short: "Show skill details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		skillName := args[0]

		skillInfo := map[string]struct {
			description string
			checks      []string
			status      string
		}{
			"iam": {
				description: "AWS IAM Security Audit",
				checks: []string{
					"Root account usage",
					"MFA enforcement",
					"Access key rotation",
					"Overprivileged policies",
					"Inline policy usage",
				},
				status: "Available",
			},
		}

		if skill, exists := skillInfo[skillName]; exists {
			fmt.Printf("\n📋 Skill: %s (%s)\n", skillName, skill.status)
			fmt.Printf("%s\n\n", skill.description)
			fmt.Println("Security Checks:")
			for _, check := range skill.checks {
				fmt.Printf("  • %s\n", check)
			}
			fmt.Println()
		} else {
			fmt.Printf("❌ Unknown skill: %s\n", skillName)
		}

		return nil
	},
}

func init() {
	skillCmd.AddCommand(skillListCmd)
	skillCmd.AddCommand(skillInfoCmd)
}
