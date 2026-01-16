package ui

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/gcuesta/drystone/internal/aws"
)

// WizardConfig holds the configuration collected from the wizard
type WizardConfig struct {
	AWSProfile   string
	AWSRegion    string
	SelectedSkills []string
	LLMProvider  string
	OutputFormats []string
}

// RunWizard runs the interactive setup wizard
func RunWizard() (*WizardConfig, error) {
	config := &WizardConfig{}

	// Print banner
	PrintBanner()

	// Step 1: AWS Profile
	PrintSectionHeader("Configuración Inicial")
	PrintStep(1, "AWS Profile")

	availableProfiles := []string{"default", "production", "staging", "development"}
	err := survey.AskOne(&survey.Select{
		Message: "Selecciona AWS Profile:",
		Options: availableProfiles,
		Default: "default",
	}, &config.AWSProfile)
	if err != nil {
		return nil, err
	}

	// Step 2: AWS Region
	PrintStep(2, "AWS Region")

	regions := aws.GetAvailableRegions()
	err = survey.AskOne(&survey.Select{
		Message: "Selecciona AWS Region:",
		Options: regions,
		Default: "us-east-1",
	}, &config.AWSRegion)
	if err != nil {
		return nil, err
	}

	// Step 3: Select Skills
	PrintStep(3, "Selecciona Skills a ejecutar")

	skillOptions := map[string]string{
		"IAM Security Audit":       "iam",
		"Internet Exposure Scan":   "exposure",
		"Network Policies Audit":   "network",
		"Vulnerability Detection":  "vulns",
	}

	var skillLabels []string
	for label := range skillOptions {
		skillLabels = append(skillLabels, label)
	}

	err = survey.AskOne(&survey.MultiSelect{
		Message: "¿Qué skills deseas ejecutar?",
		Options: skillLabels,
		Default: []string{"IAM Security Audit"},
	}, &config.SelectedSkills)
	if err != nil {
		return nil, err
	}

	// Convert labels back to skill names
	var selectedSkillNames []string
	for _, label := range config.SelectedSkills {
		if skillName, ok := skillOptions[label]; ok {
			selectedSkillNames = append(selectedSkillNames, skillName)
		}
	}
	config.SelectedSkills = selectedSkillNames

	// Step 4: LLM Provider
	PrintStep(4, "LLM Provider")

	providers := []string{"Claude (Anthropic)", "Gemini (Google) - Phase 2", "ChatGPT (OpenAI) - Phase 2"}
	defaultProvider := "Claude (Anthropic)"

	err = survey.AskOne(&survey.Select{
		Message: "Selecciona LLM Provider:",
		Options: providers,
		Default: defaultProvider,
	}, &config.LLMProvider)
	if err != nil {
		return nil, err
	}

	// Extract provider name
	if config.LLMProvider == "Claude (Anthropic)" {
		config.LLMProvider = "claude"
	} else if config.LLMProvider == "Gemini (Google) - Phase 2" {
		config.LLMProvider = "gemini"
	} else if config.LLMProvider == "ChatGPT (OpenAI) - Phase 2" {
		config.LLMProvider = "chatgpt"
	}

	// Step 5: Output Formats
	PrintStep(5, "Formatos de Output")

	formatOptions := []string{"Markdown", "JSON", "HTML"}
	defaultFormats := []string{"Markdown", "JSON"}

	err = survey.AskOne(&survey.MultiSelect{
		Message: "Selecciona formatos de reporte:",
		Options: formatOptions,
		Default: defaultFormats,
	}, &config.OutputFormats)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// PrintSummary prints a summary of the selected configuration
func PrintSummary(config *WizardConfig) {
	fmt.Println("\n📊 Resumen de Configuración")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("AWS Profile:     %s\n", config.AWSProfile)
	fmt.Printf("AWS Region:      %s\n", config.AWSRegion)
	fmt.Printf("Skills:          %v\n", config.SelectedSkills)
	fmt.Printf("LLM Provider:    %s\n", config.LLMProvider)
	fmt.Printf("Output Formats:  %v\n", config.OutputFormats)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

// ConfirmStart asks for confirmation to start the audit
func ConfirmStart() bool {
	confirm := false
	err := survey.AskOne(&survey.Confirm{
		Message: "¿Proceder con la auditoría?",
		Default: true,
	}, &confirm)

	if err != nil {
		return false
	}

	return confirm
}
