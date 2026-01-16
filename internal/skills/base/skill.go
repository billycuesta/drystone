package base

import (
	"context"

	"github.com/gcuesta/drystone/pkg/models"
)

// AWSClient represents an AWS service client
// Skills use this interface to interact with AWS services
type AWSClient interface {
	// GetAccountID returns the current AWS account ID
	GetAccountID(ctx context.Context) (string, error)

	// GetRegion returns the current AWS region
	GetRegion() string

	// Additional AWS service clients can be added as methods
}

// AgentClient represents an LLM provider client for analysis
type AgentClient interface {
	// Analyze sends evidence and checklist to the agent for analysis
	Analyze(ctx context.Context, request AnalysisRequest) (*AnalysisResponse, error)
}

// AnalysisRequest represents a request to the agent for analysis
type AnalysisRequest struct {
	// Evidence to analyze
	Evidence *models.Evidence

	// Checklist items to validate against
	Checklist []ChecklistItem

	// Additional context
	Context map[string]string
}

// AnalysisResponse represents the agent's analysis response
type AnalysisResponse struct {
	// Skill result with findings
	Result *models.SkillResult

	// Raw response from agent (for debugging)
	RawResponse string
}

// ChecklistItem represents a single security check
type ChecklistItem struct {
	// Unique identifier (e.g., "IAM-001")
	ID string `json:"id"`

	// Title of the check
	Title string `json:"title"`

	// Severity if this check fails
	Severity models.Severity `json:"severity"`

	// Description of what to check
	Description string `json:"check"`

	// Remediation steps
	Remediation string `json:"remediation"`

	// References (CIS, NIST, etc.)
	References []string `json:"references,omitempty"`
}

// Skill represents a security audit skill
type Skill interface {
	// Name returns the skill name (e.g., "iam", "exposure")
	Name() string

	// Description returns a brief description of the skill
	Description() string

	// RequiredPermissions returns the AWS permissions needed
	RequiredPermissions() []string

	// Preflight performs pre-execution checks
	Preflight(ctx context.Context, aws AWSClient) error

	// Collect gathers evidence from AWS
	Collect(ctx context.Context, aws AWSClient) (*models.Evidence, error)

	// LoadChecklist loads the security checklist for this skill
	LoadChecklist() ([]ChecklistItem, error)

	// Analyze analyzes the evidence using the agent
	Analyze(ctx context.Context, evidence *models.Evidence, agent AgentClient) (*models.SkillResult, error)
}

// BaseSkill provides common functionality for all skills
type BaseSkill struct {
	name        string
	description string
}

// NewBaseSkill creates a new BaseSkill instance
func NewBaseSkill(name, description string) *BaseSkill {
	return &BaseSkill{
		name:        name,
		description: description,
	}
}

// Name returns the skill name
func (b *BaseSkill) Name() string {
	return b.name
}

// Description returns the skill description
func (b *BaseSkill) Description() string {
	return b.description
}
