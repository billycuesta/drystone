package agent

import (
	"encoding/json"
	"fmt"

	"github.com/gcuesta/drystone/pkg/models"
)

// Validator validates agent responses against expected schema
type Validator struct {
	strictMode bool
}

// NewValidator creates a new validator
func NewValidator(strict bool) *Validator {
	return &Validator{
		strictMode: strict,
	}
}

// ValidateSkillResult validates a skill result structure
func (v *Validator) ValidateSkillResult(result *models.SkillResult) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}

	// Validate skill name
	if result.SkillName == "" {
		return fmt.Errorf("skill_name is required")
	}

	// Validate risk score range
	if result.RiskScore < 0 || result.RiskScore > 10 {
		return fmt.Errorf("risk_score must be between 0 and 10, got: %.2f", result.RiskScore)
	}

	// Validate findings
	if len(result.Findings) == 0 {
		// In non-strict mode, empty findings is acceptable (no issues found)
		if v.strictMode {
			return fmt.Errorf("findings array is empty")
		}
		return nil
	}

	// Validate each finding
	for i, finding := range result.Findings {
		if err := v.ValidateFinding(finding); err != nil {
			return fmt.Errorf("finding[%d] invalid: %w", i, err)
		}
	}

	return nil
}

// ValidateFinding validates a single finding
func (v *Validator) ValidateFinding(finding models.Finding) error {
	// Required fields
	if finding.ID == "" {
		return fmt.Errorf("id is required")
	}

	if finding.Title == "" {
		return fmt.Errorf("title is required")
	}

	// Validate severity
	validSeverities := map[models.Severity]bool{
		models.SeverityCritical: true,
		models.SeverityHigh:     true,
		models.SeverityMedium:   true,
		models.SeverityLow:      true,
		models.SeverityInfo:     true,
	}

	if !validSeverities[finding.Severity] {
		return fmt.Errorf("invalid severity: %s (must be Critical, High, Medium, Low, or Info)", finding.Severity)
	}

	// Validate risk score
	if finding.RiskScore < 0 || finding.RiskScore > 10 {
		return fmt.Errorf("risk_score must be between 0 and 10, got: %.2f", finding.RiskScore)
	}

	// In strict mode, require evidence and remediation
	if v.strictMode {
		if finding.Evidence == "" {
			return fmt.Errorf("evidence is required in strict mode")
		}

		if len(finding.Remediation) == 0 {
			return fmt.Errorf("remediation steps are required in strict mode")
		}
	}

	return nil
}

// ValidateJSON validates raw JSON against expected schema
func (v *Validator) ValidateJSON(rawJSON string) error {
	// Try to parse as SkillResult
	var temp struct {
		Findings  []models.Finding `json:"findings"`
		RiskScore float64          `json:"risk_score"`
		Summary   string           `json:"summary"`
	}

	if err := json.Unmarshal([]byte(rawJSON), &temp); err != nil {
		return fmt.Errorf("invalid JSON structure: %w", err)
	}

	// Validate risk score
	if temp.RiskScore < 0 || temp.RiskScore > 10 {
		return fmt.Errorf("risk_score out of range: %.2f", temp.RiskScore)
	}

	// Validate findings
	for i, finding := range temp.Findings {
		if err := v.ValidateFinding(finding); err != nil {
			return fmt.Errorf("finding[%d] invalid: %w", i, err)
		}
	}

	return nil
}

// SanitizeSkillResult attempts to fix common issues in skill results
func (v *Validator) SanitizeSkillResult(result *models.SkillResult) *models.SkillResult {
	if result == nil {
		return result
	}

	// Clamp risk score to valid range
	if result.RiskScore < 0 {
		result.RiskScore = 0
	} else if result.RiskScore > 10 {
		result.RiskScore = 10
	}

	// Sanitize findings
	for i := range result.Findings {
		result.Findings[i] = v.SanitizeFinding(result.Findings[i])
	}

	return result
}

// SanitizeFinding attempts to fix common issues in findings
func (v *Validator) SanitizeFinding(finding models.Finding) models.Finding {
	// Clamp risk score
	if finding.RiskScore < 0 {
		finding.RiskScore = 0
	} else if finding.RiskScore > 10 {
		finding.RiskScore = 10
	}

	// Normalize severity
	switch finding.Severity {
	case "critical", "CRITICAL":
		finding.Severity = models.SeverityCritical
	case "high", "HIGH":
		finding.Severity = models.SeverityHigh
	case "medium", "MEDIUM":
		finding.Severity = models.SeverityMedium
	case "low", "LOW":
		finding.Severity = models.SeverityLow
	case "info", "INFO", "informational", "INFORMATIONAL":
		finding.Severity = models.SeverityInfo
	}

	// Initialize empty slices if nil
	if finding.Remediation == nil {
		finding.Remediation = []string{}
	}
	if finding.References == nil {
		finding.References = []string{}
	}
	if finding.AffectedResources == nil {
		finding.AffectedResources = []string{}
	}

	return finding
}
