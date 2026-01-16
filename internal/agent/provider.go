package agent

import (
	"context"
	"fmt"

	"github.com/gcuesta/drystone/internal/skills/base"
)

// ProviderType represents the LLM provider type
type ProviderType string

const (
	ProviderClaude  ProviderType = "claude"
	ProviderGemini  ProviderType = "gemini"
	ProviderChatGPT ProviderType = "chatgpt"
)

// Provider represents an LLM provider for analysis
type Provider interface {
	// Name returns the provider name
	Name() string

	// Analyze performs analysis using the provider's LLM
	Analyze(ctx context.Context, request base.AnalysisRequest) (*base.AnalysisResponse, error)

	// ValidateConfig checks if the provider is properly configured
	ValidateConfig() error
}

// Config holds provider configuration
type Config struct {
	// Provider type
	Provider ProviderType

	// API keys
	ClaudeAPIKey  string
	GeminiAPIKey  string
	ChatGPTAPIKey string

	// Model configurations
	ClaudeModel  string // e.g., "claude-3-5-sonnet-20241022"
	GeminiModel  string // e.g., "gemini-pro"
	ChatGPTModel string // e.g., "gpt-4"

	// Validation settings
	MaxRetries      int
	ValidateSchema  bool
	ResponseTimeout int // seconds
}

// NewProvider creates a provider based on configuration
func NewProvider(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case ProviderClaude:
		return NewClaudeProvider(cfg)
	case ProviderGemini:
		return nil, fmt.Errorf("gemini provider not yet implemented (Phase 2)")
	case ProviderChatGPT:
		return nil, fmt.Errorf("chatgpt provider not yet implemented (Phase 2)")
	default:
		return nil, fmt.Errorf("unknown provider: %s", cfg.Provider)
	}
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	return Config{
		Provider:        ProviderClaude,
		ClaudeModel:     "claude-3-5-sonnet-20241022",
		MaxRetries:      2,
		ValidateSchema:  true,
		ResponseTimeout: 300, // 5 minutes
	}
}
