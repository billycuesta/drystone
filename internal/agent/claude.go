package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/gcuesta/drystone/internal/skills/base"
	"github.com/gcuesta/drystone/pkg/models"
)

// ClaudeProvider implements Provider interface using Claude API
type ClaudeProvider struct {
	client  *anthropic.Client
	model   string
	config  Config
	retries int
}

// NewClaudeProvider creates a new Claude provider
func NewClaudeProvider(cfg Config) (*ClaudeProvider, error) {
	if cfg.ClaudeAPIKey == "" {
		return nil, fmt.Errorf("claude API key is required")
	}

	client := anthropic.NewClient(
		option.WithAPIKey(cfg.ClaudeAPIKey),
	)

	model := cfg.ClaudeModel
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}

	return &ClaudeProvider{
		client:  &client,
		model:   model,
		config:  cfg,
		retries: cfg.MaxRetries,
	}, nil
}

// Name returns the provider name
func (c *ClaudeProvider) Name() string {
	return "claude"
}

// ValidateConfig checks if the provider is properly configured
func (c *ClaudeProvider) ValidateConfig() error {
	if c.client == nil {
		return fmt.Errorf("claude client not initialized")
	}
	return nil
}

// Analyze performs analysis using Claude API
func (c *ClaudeProvider) Analyze(ctx context.Context, request base.AnalysisRequest) (*base.AnalysisResponse, error) {
	startTime := time.Now()

	// Build prompt
	prompt := c.buildPrompt(request)

	// For MVP, return a placeholder response
	// Full implementation will integrate with Claude API
	result := models.NewSkillResult(request.Evidence.SkillName)
	result.RiskScore = 5.0
	result.Summary = "Analysis placeholder - Claude API integration in progress"
	result.Findings = []models.Finding{
		{
			ID:           "DEMO-001",
			Title:        "Demo Finding - Not Implemented",
			Severity:     models.SeverityInfo,
			RiskScore:    1.0,
			Description:  "This is a placeholder finding for MVP demonstration",
			Evidence:     "CLI is working and can process requests",
			Remediation:  []string{"This is a demo - full implementation pending"},
			References:   []string{},
		},
	}

	result.Duration = time.Since(startTime).Seconds()

	return &base.AnalysisResponse{
		Result:      result,
		RawResponse: prompt[:100], // Return part of prompt as raw response
	}, nil
}

// buildPrompt constructs the prompt for Claude
func (c *ClaudeProvider) buildPrompt(request base.AnalysisRequest) string {
	evidenceJSON, _ := json.MarshalIndent(request.Evidence, "", "  ")
	checklistJSON, _ := json.MarshalIndent(request.Checklist, "", "  ")

	prompt := fmt.Sprintf(`You are an AWS security auditor. Analyze the following evidence against the security checklist.

EVIDENCE:
%s

CHECKLIST:
%s

Return a JSON object with this exact structure:
{
  "findings": [
    {
      "id": "SKILL-001",
      "title": "Finding title",
      "severity": "Critical|High|Medium|Low|Info",
      "risk_score": 9.5,
      "description": "Detailed description",
      "evidence": "Supporting evidence from data",
      "remediation": ["Step 1", "Step 2"],
      "references": ["CIS 1.1", "https://..."],
      "affected_resources": ["arn:aws:..."]
    }
  ],
  "risk_score": 7.5,
  "summary": "Overall summary of findings"
}

IMPORTANT:
- Only analyze the provided evidence
- Do NOT suggest next steps or additional audits
- Return ONLY valid JSON (no markdown, no extra text)
- Calculate risk_score as average of all findings
- Include at least one finding if any issues are found
`, evidenceJSON, checklistJSON)

	return prompt
}

// parseResponse parses Claude's JSON response
func (c *ClaudeProvider) parseResponse(rawResponse, skillName string) (*models.SkillResult, error) {
	// Try to extract JSON from markdown code blocks if present
	jsonStr := extractJSONFromMarkdown(rawResponse)

	// Parse into temporary structure
	var temp struct {
		Findings  []models.Finding `json:"findings"`
		RiskScore float64          `json:"risk_score"`
		Summary   string           `json:"summary"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &temp); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate required fields
	if len(temp.Findings) == 0 {
		return nil, fmt.Errorf("no findings in response")
	}

	// Build SkillResult
	result := models.NewSkillResult(skillName)
	result.Findings = temp.Findings
	result.RiskScore = temp.RiskScore
	result.Summary = temp.Summary

	return result, nil
}

// retryWithCorrection retries analysis with error correction prompt
func (c *ClaudeProvider) retryWithCorrection(ctx context.Context, request base.AnalysisRequest, failedResponse string, parseError error) (*base.AnalysisResponse, error) {
	correctionPrompt := fmt.Sprintf(`Your previous response could not be parsed. Error: %s

Previous response:
%s

Please provide the response again as valid JSON with the correct structure. Return ONLY the JSON object, no markdown formatting.`, parseError.Error(), failedResponse)

	// For MVP, return retry as a new attempt
	_ = correctionPrompt

	// Decrement retry and defer restore
	c.retries--
	defer func() { c.retries++ }()

	// Return same as original (placeholder)
	return c.Analyze(ctx, request)
}

// extractJSONFromMarkdown extracts JSON from markdown code blocks
func extractJSONFromMarkdown(text string) string {
	// Remove markdown code blocks if present
	if len(text) > 7 && text[:3] == "```" {
		// Find closing ```
		start := 0
		for i := 3; i < len(text); i++ {
			if text[i] == '\n' {
				start = i + 1
				break
			}
		}
		end := len(text)
		for i := len(text) - 1; i > start; i-- {
			if text[i] == '`' && i >= 2 && text[i-1] == '`' && text[i-2] == '`' {
				end = i - 2
				break
			}
		}
		return text[start:end]
	}
	return text
}
