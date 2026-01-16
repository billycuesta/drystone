package models

import "time"

// Evidence represents raw data collected from AWS
type Evidence struct {
	// Skill that collected this evidence
	SkillName string `json:"skill_name"`

	// Timestamp of collection
	CollectedAt time.Time `json:"collected_at"`

	// AWS Account ID
	AccountID string `json:"account_id"`

	// AWS Region
	Region string `json:"region"`

	// Raw data collected (skill-specific structure)
	Data map[string]interface{} `json:"data"`

	// Metadata about collection
	Metadata EvidenceMetadata `json:"metadata"`
}

// EvidenceMetadata contains information about the collection process
type EvidenceMetadata struct {
	// Collection duration in seconds
	Duration float64 `json:"duration_seconds"`

	// Number of API calls made
	APICallCount int `json:"api_call_count"`

	// Any warnings during collection
	Warnings []string `json:"warnings,omitempty"`

	// Collection errors (non-fatal)
	Errors []string `json:"errors,omitempty"`
}

// NewEvidence creates a new Evidence instance
func NewEvidence(skillName, accountID, region string) *Evidence {
	return &Evidence{
		SkillName:   skillName,
		CollectedAt: time.Now(),
		AccountID:   accountID,
		Region:      region,
		Data:        make(map[string]interface{}),
		Metadata: EvidenceMetadata{
			Warnings: []string{},
			Errors:   []string{},
		},
	}
}

// AddData adds data to the evidence
func (e *Evidence) AddData(key string, value interface{}) {
	e.Data[key] = value
}

// AddWarning adds a warning to the evidence metadata
func (e *Evidence) AddWarning(warning string) {
	e.Metadata.Warnings = append(e.Metadata.Warnings, warning)
}

// AddError adds an error to the evidence metadata
func (e *Evidence) AddError(err string) {
	e.Metadata.Errors = append(e.Metadata.Errors, err)
}
