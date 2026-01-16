package models

import "time"

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
)

// Finding represents a security finding identified by the agent
type Finding struct {
	// Unique identifier (e.g., "IAM-001")
	ID string `json:"id"`

	// Finding title
	Title string `json:"title"`

	// Severity level
	Severity Severity `json:"severity"`

	// Risk score (0-10)
	RiskScore float64 `json:"risk_score"`

	// Description of the finding
	Description string `json:"description"`

	// Evidence supporting this finding (references to raw data)
	Evidence string `json:"evidence"`

	// Remediation steps
	Remediation []string `json:"remediation"`

	// References (CIS, NIST, etc.)
	References []string `json:"references,omitempty"`

	// Affected resources
	AffectedResources []string `json:"affected_resources,omitempty"`

	// Timestamp when finding was created
	FoundAt time.Time `json:"found_at"`
}

// SkillResult represents the complete analysis result from a skill
type SkillResult struct {
	// Skill that generated these findings
	SkillName string `json:"skill_name"`

	// Overall risk score for this skill (0-10)
	RiskScore float64 `json:"risk_score"`

	// List of findings
	Findings []Finding `json:"findings"`

	// Summary of analysis
	Summary string `json:"summary"`

	// Analysis timestamp
	AnalyzedAt time.Time `json:"analyzed_at"`

	// Analysis duration in seconds
	Duration float64 `json:"duration_seconds"`
}

// AuditReport represents the complete audit report
type AuditReport struct {
	// Session ID
	SessionID string `json:"session_id"`

	// AWS Account ID
	AccountID string `json:"account_id"`

	// Timestamp of audit start
	StartedAt time.Time `json:"started_at"`

	// Timestamp of audit completion
	CompletedAt time.Time `json:"completed_at"`

	// Overall risk score (aggregated from all skills)
	OverallRiskScore float64 `json:"overall_risk_score"`

	// Results from each skill
	SkillResults []SkillResult `json:"skill_results"`

	// Total number of findings by severity
	FindingsSummary FindingsSummary `json:"findings_summary"`

	// Correlations between skills (attack chains)
	Correlations []Correlation `json:"correlations,omitempty"`
}

// FindingsSummary provides a count of findings by severity
type FindingsSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Correlation represents a cross-skill finding correlation
type Correlation struct {
	// Unique identifier
	ID string `json:"id"`

	// Title of the correlation
	Title string `json:"title"`

	// Risk score for this correlation
	RiskScore float64 `json:"risk_score"`

	// Related findings (by ID)
	RelatedFindings []string `json:"related_findings"`

	// Description of the attack chain or correlation
	Description string `json:"description"`
}

// NewFinding creates a new Finding instance
func NewFinding(id, title string, severity Severity, riskScore float64) *Finding {
	return &Finding{
		ID:                id,
		Title:             title,
		Severity:          severity,
		RiskScore:         riskScore,
		Remediation:       []string{},
		References:        []string{},
		AffectedResources: []string{},
		FoundAt:           time.Now(),
	}
}

// NewSkillResult creates a new SkillResult instance
func NewSkillResult(skillName string) *SkillResult {
	return &SkillResult{
		SkillName:  skillName,
		Findings:   []Finding{},
		AnalyzedAt: time.Now(),
	}
}

// AddFinding adds a finding to the skill result
func (sr *SkillResult) AddFinding(finding Finding) {
	sr.Findings = append(sr.Findings, finding)
}

// CalculateRiskScore calculates the overall risk score based on findings
func (sr *SkillResult) CalculateRiskScore() {
	if len(sr.Findings) == 0 {
		sr.RiskScore = 0
		return
	}

	var total float64
	for _, f := range sr.Findings {
		total += f.RiskScore
	}

	sr.RiskScore = total / float64(len(sr.Findings))
}
