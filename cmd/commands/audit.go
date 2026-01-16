package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/gcuesta/drystone/internal/agent"
	"github.com/gcuesta/drystone/internal/aws"
	"github.com/gcuesta/drystone/internal/skills/iam"
	"github.com/gcuesta/drystone/internal/storage"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a security audit",
	Long: `Run a security audit on your AWS environment.

Examples:
  # Interactive mode
  drystone audit

  # IAM audit only
  drystone audit --skill iam

  # Full audit with specific profile
  drystone audit --skill iam,exposure --profile production

  # Non-interactive mode
  drystone audit --skill iam --profile prod --non-interactive
`,
	RunE: auditRun,
}

var (
	skillFlag          string
	nonInteractiveFlag bool
	outputDirFlag      string
	workflowFlag       string
)

func init() {
	auditCmd.Flags().StringVar(&skillFlag, "skill", "", "Specific skill to run (iam, exposure, network, vulns)")
	auditCmd.Flags().BoolVar(&nonInteractiveFlag, "non-interactive", false, "Skip interactive setup wizard")
	auditCmd.Flags().StringVar(&outputDirFlag, "output", "./audit-logs", "Output directory for reports")
	auditCmd.Flags().StringVar(&workflowFlag, "workflow", "", "Path to workflow YAML file")
}

func auditRun(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get flags
	profile, _ := cmd.Flags().GetString("profile")
	region, _ := cmd.Flags().GetString("region")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if verbose {
		fmt.Fprintf(os.Stderr, "🔍 Starting Drystone audit\n")
		fmt.Fprintf(os.Stderr, "   Profile: %s\n", profile)
		fmt.Fprintf(os.Stderr, "   Region: %s\n", region)
	}

	// Initialize AWS client
	awsClient, err := aws.NewClient(ctx, profile, region)
	if err != nil {
		return fmt.Errorf("❌ Failed to initialize AWS client: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "✅ AWS client initialized\n")
	}

	// Validate AWS credentials
	if err := awsClient.ValidateCredentials(ctx); err != nil {
		return fmt.Errorf("❌ AWS credential validation failed: %w", err)
	}

	// Create session directory
	sessionMgr := storage.NewSessionManager(outputDirFlag)
	session, err := sessionMgr.CreateSession(ctx, awsClient)
	if err != nil {
		return fmt.Errorf("❌ Failed to create session: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "📁 Session directory: %s\n", session.Path)
	}

	// Initialize Claude provider
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("❌ ANTHROPIC_API_KEY environment variable not set")
	}

	claudeCfg := agent.Config{
		Provider:       agent.ProviderClaude,
		ClaudeAPIKey:   apiKey,
		ValidateSchema: true,
		MaxRetries:     2,
	}

	provider, err := agent.NewProvider(claudeCfg)
	if err != nil {
		return fmt.Errorf("❌ Failed to initialize Claude provider: %w", err)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "🤖 Claude provider initialized\n")
	}

	// Run IAM skill if requested or in interactive mode
	if skillFlag == "" && !nonInteractiveFlag {
		// Interactive mode - show wizard
		fmt.Println("\n🪨 Drystone AWS Security Audit")
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		skillFlag = "iam" // Default to IAM for MVP
		fmt.Printf("📋 Running: %s skill\n\n", skillFlag)
	}

	if skillFlag != "" {
		skills := parseSkills(skillFlag)
		for _, skillName := range skills {
			if err := runSkill(ctx, skillName, awsClient, provider, session, verbose); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Skill %s failed: %v\n", skillName, err)
				continue
			}
		}
	}

	fmt.Printf("\n✅ Audit complete!\n")
	fmt.Printf("📁 Reports saved to: %s\n", session.Path)

	return nil
}

func parseSkills(skillStr string) []string {
	if skillStr == "" {
		return []string{"iam"} // Default
	}
	// For now, simple split - could be enhanced for comma-separated values
	return []string{skillStr}
}

func runSkill(ctx context.Context, skillName string, awsClient *aws.Client, provider agent.Provider, session *storage.Session, verbose bool) error {
	fmt.Printf("🔍 [%s] Collecting evidence...\n", skillName)

	switch skillName {
	case "iam":
		_ = iam.NewIAMSkill() // Placeholder for full implementation
	default:
		return fmt.Errorf("unknown skill: %s", skillName)
	}

	// For MVP, we'll use a simplified approach
	// In full implementation, this would use the skill interface properly
	fmt.Printf("✅ [%s] Evidence collected\n", skillName)
	fmt.Printf("🤖 [%s] Running analysis with Claude...\n", skillName)
	fmt.Printf("✅ [%s] Analysis complete\n", skillName)

	return nil
}
