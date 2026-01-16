package iam

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/gcuesta/drystone/internal/skills/base"
	"github.com/gcuesta/drystone/pkg/models"
)

//go:embed checklist.json
var checklistJSON []byte

// Skill implements the IAM security audit skill
type Skill struct {
	*base.BaseSkill
	collector *Collector
}

// NewIAMSkill creates a new IAM skill
func NewIAMSkill() *Skill {
	return &Skill{
		BaseSkill: base.NewBaseSkill(
			"iam",
			"AWS IAM Security Audit - Checks for IAM misconfigurations, excessive permissions, and compliance issues",
		),
	}
}

// RequiredPermissions returns the IAM permissions needed for this skill
func (s *Skill) RequiredPermissions() []string {
	return []string{
		"iam:ListUsers",
		"iam:ListGroups",
		"iam:ListRoles",
		"iam:ListPolicies",
		"iam:ListAccessKeys",
		"iam:ListMFADevices",
		"iam:ListGroupsForUser",
		"iam:GetGroup",
		"iam:GetGroupPolicy",
		"iam:GetUserPolicy",
		"iam:GetRolePolicy",
		"iam:GetLoginProfile",
		"iam:GetPolicyVersion",
		"iam:GetAccountSummary",
		"iam:GetCredentialReport",
		"cloudtrail:LookupEvents",
	}
}

// Preflight performs pre-execution checks
func (s *Skill) Preflight(ctx context.Context, aws base.AWSClient) error {
	// Check that AWS client is available
	if aws == nil {
		return fmt.Errorf("AWS client is required")
	}

	// In a real implementation, verify IAM permissions
	return nil
}

// Collect gathers IAM evidence from AWS
func (s *Skill) Collect(ctx context.Context, aws base.AWSClient) (*models.Evidence, error) {
	// Get AWS clients from context or parameter
	// This is a placeholder - in real implementation, aws parameter will have the clients

	// For now, we'll assume this is called with proper AWS clients initialized
	// In actual implementation:
	// iamClient := aws.(AWSClientWithServices).IAMClient()
	// cloudtrailClient := aws.(AWSClientWithServices).CloudTrailClient()

	// Create a collector (in real implementation, clients will come from aws parameter)
	var iamClient *iam.Client
	var cloudtrailClient *cloudtrail.Client

	// TODO: Extract clients from aws parameter once AWSClient implementation is complete

	if iamClient == nil {
		return nil, fmt.Errorf("IAM client not initialized")
	}

	collector := NewCollector(iamClient, cloudtrailClient)
	s.collector = collector

	// Get account ID
	accountID, err := aws.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	// Collect evidence
	evidence, err := collector.Collect(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to collect IAM data: %w", err)
	}

	return evidence, nil
}

// LoadChecklist loads the IAM security checklist
func (s *Skill) LoadChecklist() ([]base.ChecklistItem, error) {
	var checklist []base.ChecklistItem

	if err := json.Unmarshal(checklistJSON, &checklist); err != nil {
		return nil, fmt.Errorf("failed to load checklist: %w", err)
	}

	return checklist, nil
}

// Analyze analyzes the IAM evidence using Claude
func (s *Skill) Analyze(ctx context.Context, evidence *models.Evidence, agent base.AgentClient) (*models.SkillResult, error) {
	if evidence == nil {
		return nil, fmt.Errorf("evidence is required")
	}

	if agent == nil {
		return nil, fmt.Errorf("agent client is required")
	}

	// Load checklist
	checklist, err := s.LoadChecklist()
	if err != nil {
		return nil, fmt.Errorf("failed to load checklist: %w", err)
	}

	// Create analysis request
	request := base.AnalysisRequest{
		Evidence:  evidence,
		Checklist: checklist,
		Context: map[string]string{
			"skill": s.Name(),
		},
	}

	// Call agent
	response, err := agent.Analyze(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("agent analysis failed: %w", err)
	}

	if response == nil || response.Result == nil {
		return nil, fmt.Errorf("empty response from agent")
	}

	return response.Result, nil
}

// String returns the skill name
func (s *Skill) String() string {
	return fmt.Sprintf("%s: %s", s.Name(), s.Description())
}
