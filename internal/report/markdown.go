package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gcuesta/drystone/pkg/models"
)

// MarkdownGenerator generates Shannon-style Markdown reports
type MarkdownGenerator struct {
	report *models.AuditReport
}

// NewMarkdownGenerator creates a new Markdown report generator
func NewMarkdownGenerator(report *models.AuditReport) *MarkdownGenerator {
	return &MarkdownGenerator{
		report: report,
	}
}

// Generate generates the Markdown report
func (g *MarkdownGenerator) Generate() string {
	var sb strings.Builder

	// Header
	sb.WriteString(g.generateHeader())

	// Executive Summary
	sb.WriteString(g.generateExecutiveSummary())

	// Findings by severity
	sb.WriteString(g.generateFindingsBySkill())

	// Remediation guide
	sb.WriteString(g.generateRemediationGuide())

	// Appendix
	sb.WriteString(g.generateAppendix())

	return sb.String()
}

// generateHeader generates the report header
func (g *MarkdownGenerator) generateHeader() string {
	var sb strings.Builder

	sb.WriteString("# AWS Security Audit Report\n\n")
	sb.WriteString("**Drystone** - AWS Security Audit CLI powered by Claude\n\n")

	// Session info
	sb.WriteString("---\n\n")
	sb.WriteString("| Information | Value |\n")
	sb.WriteString("|---|---|\n")
	sb.WriteString(fmt.Sprintf("| **Session ID** | `%s` |\n", g.report.SessionID))
	sb.WriteString(fmt.Sprintf("| **Account ID** | `%s` |\n", g.report.AccountID))
	sb.WriteString(fmt.Sprintf("| **Date** | %s UTC |\n", g.report.StartedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("| **Duration** | %.1f seconds |\n", g.report.CompletedAt.Sub(g.report.StartedAt).Seconds()))
	sb.WriteString(fmt.Sprintf("| **Overall Risk Score** | **%.1f/10** |\n\n", g.report.OverallRiskScore))

	return sb.String()
}

// generateExecutiveSummary generates the executive summary
func (g *MarkdownGenerator) generateExecutiveSummary() string {
	var sb strings.Builder

	sb.WriteString("## Executive Summary\n\n")

	// Risk score with indicator
	riskLevel := getRiskLevel(g.report.OverallRiskScore)
	sb.WriteString(fmt.Sprintf("**Overall Risk Level: %s** (Score: %.1f/10)\n\n", riskLevel, g.report.OverallRiskScore))

	// Summary table
	sb.WriteString("### Finding Summary\n\n")
	sb.WriteString("| Severity | Count | Percentage |\n")
	sb.WriteString("|---|---|---|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 Critical | %d | %.0f%% |\n",
		g.report.FindingsSummary.Critical,
		float64(g.report.FindingsSummary.Critical)/float64(g.report.FindingsSummary.Total)*100,
	))
	sb.WriteString(fmt.Sprintf("| 🟠 High | %d | %.0f%% |\n",
		g.report.FindingsSummary.High,
		float64(g.report.FindingsSummary.High)/float64(g.report.FindingsSummary.Total)*100,
	))
	sb.WriteString(fmt.Sprintf("| 🟡 Medium | %d | %.0f%% |\n",
		g.report.FindingsSummary.Medium,
		float64(g.report.FindingsSummary.Medium)/float64(g.report.FindingsSummary.Total)*100,
	))
	sb.WriteString(fmt.Sprintf("| 🔵 Low | %d | %.0f%% |\n",
		g.report.FindingsSummary.Low,
		float64(g.report.FindingsSummary.Low)/float64(g.report.FindingsSummary.Total)*100,
	))
	sb.WriteString(fmt.Sprintf("| ℹ️ Info | %d | %.0f%% |\n\n",
		g.report.FindingsSummary.Info,
		float64(g.report.FindingsSummary.Info)/float64(g.report.FindingsSummary.Total)*100,
	))

	return sb.String()
}

// generateFindingsBySkill generates findings organized by skill
func (g *MarkdownGenerator) generateFindingsBySkill() string {
	var sb strings.Builder

	// Sort findings by severity
	for _, skillResult := range g.report.SkillResults {
		sb.WriteString(fmt.Sprintf("## %s Audit Results\n\n", strings.ToUpper(skillResult.SkillName[:1])+skillResult.SkillName[1:]))

		if len(skillResult.Findings) == 0 {
			sb.WriteString("✅ No critical findings detected.\n\n")
			continue
		}

		// Group by severity
		bySeverity := groupBySeverity(skillResult.Findings)
		severityOrder := []models.Severity{
			models.SeverityCritical,
			models.SeverityHigh,
			models.SeverityMedium,
			models.SeverityLow,
			models.SeverityInfo,
		}

		for _, severity := range severityOrder {
			findings, exists := bySeverity[severity]
			if !exists || len(findings) == 0 {
				continue
			}

			sb.WriteString(fmt.Sprintf("### %s Findings (%d)\n\n", severity, len(findings)))

			for _, finding := range findings {
				sb.WriteString(g.generateFindingDetails(finding))
			}
		}
	}

	return sb.String()
}

// generateFindingDetails generates detailed finding information
func (g *MarkdownGenerator) generateFindingDetails(finding models.Finding) string {
	var sb strings.Builder

	// Title with ID
	sb.WriteString(fmt.Sprintf("#### [%s] %s\n\n", finding.ID, finding.Title))

	// Risk score badge
	sb.WriteString(fmt.Sprintf("**Risk Score:** %.1f/10 | **Severity:** %s\n\n", finding.RiskScore, finding.Severity))

	// Description
	sb.WriteString(fmt.Sprintf("**Description:**\n%s\n\n", finding.Description))

	// Evidence
	if finding.Evidence != "" {
		sb.WriteString("**Evidence:**\n")
		sb.WriteString("```json\n")
		sb.WriteString(finding.Evidence + "\n")
		sb.WriteString("```\n\n")
	}

	// Affected Resources
	if len(finding.AffectedResources) > 0 {
		sb.WriteString("**Affected Resources:**\n")
		for _, resource := range finding.AffectedResources {
			sb.WriteString(fmt.Sprintf("- `%s`\n", resource))
		}
		sb.WriteString("\n")
	}

	// Remediation
	if len(finding.Remediation) > 0 {
		sb.WriteString("**Remediation Steps:**\n\n")
		for i, step := range finding.Remediation {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}

	// References
	if len(finding.References) > 0 {
		sb.WriteString("**References:**\n")
		for _, ref := range finding.References {
			if strings.HasPrefix(ref, "http") {
				sb.WriteString(fmt.Sprintf("- [%s](%s)\n", ref, ref))
			} else {
				sb.WriteString(fmt.Sprintf("- %s\n", ref))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n\n")

	return sb.String()
}

// generateRemediationGuide generates a prioritized remediation guide
func (g *MarkdownGenerator) generateRemediationGuide() string {
	var sb strings.Builder

	sb.WriteString("## Remediation Guide\n\n")
	sb.WriteString("### Priority Order\n\n")
	sb.WriteString("Remediate findings in this order to maximize security impact:\n\n")

	// Collect all findings
	var allFindings []models.Finding
	for _, skillResult := range g.report.SkillResults {
		allFindings = append(allFindings, skillResult.Findings...)
	}

	// Sort by risk score (highest first)
	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].RiskScore > allFindings[j].RiskScore
	})

	// Show top 10
	limit := 10
	if len(allFindings) < limit {
		limit = len(allFindings)
	}

	for i, finding := range allFindings[:limit] {
		sb.WriteString(fmt.Sprintf("%d. **[%s]** %s (Risk: %.1f/10)\n", i+1, finding.ID, finding.Title, finding.RiskScore))
	}
	sb.WriteString("\n")

	return sb.String()
}

// generateAppendix generates the appendix
func (g *MarkdownGenerator) generateAppendix() string {
	var sb strings.Builder

	sb.WriteString("## Appendix\n\n")

	sb.WriteString("### Methodology\n\n")
	sb.WriteString("This audit was performed using Drystone, an automated AWS security auditing tool that:\n\n")
	sb.WriteString("1. **Collects** raw data from AWS APIs\n")
	sb.WriteString("2. **Analyzes** against industry benchmarks (CIS, NIST)\n")
	sb.WriteString("3. **Correlates** findings across services\n")
	sb.WriteString("4. **Reports** with actionable recommendations\n\n")

	sb.WriteString("### Skill Details\n\n")
	for _, skillResult := range g.report.SkillResults {
		sb.WriteString(fmt.Sprintf("**%s**\n", strings.ToUpper(skillResult.SkillName)))
		sb.WriteString(fmt.Sprintf("- Duration: %.1f seconds\n", skillResult.Duration))
		sb.WriteString(fmt.Sprintf("- Findings: %d\n", len(skillResult.Findings)))
		sb.WriteString(fmt.Sprintf("- Risk Score: %.1f/10\n", skillResult.RiskScore))
		if skillResult.Summary != "" {
			sb.WriteString(fmt.Sprintf("- Summary: %s\n", skillResult.Summary))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### Report Information\n\n")
	sb.WriteString(fmt.Sprintf("- Generated: %s\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("- Tool: Drystone v0.1.0-alpha\n")
	sb.WriteString("- Provider: Claude (Anthropic)\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString("**Disclaimer:** This report is for informational purposes. Review findings with your security team and AWS support.\n")

	return sb.String()
}

// Helper functions

func getRiskLevel(score float64) string {
	if score >= 9 {
		return "🔴 Critical"
	} else if score >= 7 {
		return "🟠 High"
	} else if score >= 5 {
		return "🟡 Medium"
	} else if score >= 3 {
		return "🔵 Low"
	} else {
		return "✅ Minimal"
	}
}

func groupBySeverity(findings []models.Finding) map[models.Severity][]models.Finding {
	grouped := make(map[models.Severity][]models.Finding)
	for _, finding := range findings {
		grouped[finding.Severity] = append(grouped[finding.Severity], finding)
	}
	return grouped
}
