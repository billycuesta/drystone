package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gcuesta/drystone/internal/skills/base"
)

// Session represents an audit session
type Session struct {
	// Unique session identifier
	ID string `json:"id"`

	// Session path on disk
	Path string `json:"path"`

	// AWS Account ID
	AccountID string `json:"account_id"`

	// AWS Region
	Region string `json:"region"`

	// Timestamp when session started
	StartedAt time.Time `json:"started_at"`

	// Timestamp when session ended
	EndedAt time.Time `json:"ended_at,omitempty"`

	// Skills executed
	Skills []string `json:"skills"`

	// Overall risk score
	RiskScore float64 `json:"risk_score,omitempty"`
}

// SessionMetadata represents session metadata stored on disk
type SessionMetadata struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Region    string    `json:"region"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	Skills    []string  `json:"skills"`
	RiskScore float64   `json:"risk_score,omitempty"`
}

// SessionManager manages audit sessions
type SessionManager struct {
	basePath string
}

// NewSessionManager creates a new session manager
func NewSessionManager(basePath string) *SessionManager {
	return &SessionManager{
		basePath: basePath,
	}
}

// CreateSession creates a new audit session
func (sm *SessionManager) CreateSession(ctx context.Context, aws base.AWSClient) (*Session, error) {
	accountID, err := aws.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get account ID: %w", err)
	}

	region := aws.GetRegion()
	sessionID := fmt.Sprintf("%s_%s", accountID, time.Now().Format("2006-01-02T15-04-05"))

	// Create session directory structure
	sessionPath := filepath.Join(sm.basePath, sessionID)

	dirs := []string{
		sessionPath,
		filepath.Join(sessionPath, "evidence"),
		filepath.Join(sessionPath, "evidence", "iam"),
		filepath.Join(sessionPath, "findings"),
		filepath.Join(sessionPath, "reports"),
		filepath.Join(sessionPath, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	session := &Session{
		ID:        sessionID,
		Path:      sessionPath,
		AccountID: accountID,
		Region:    region,
		StartedAt: time.Now(),
		Skills:    []string{},
	}

	// Save session metadata
	if err := sm.saveSessionMetadata(session); err != nil {
		return nil, fmt.Errorf("failed to save session metadata: %w", err)
	}

	return session, nil
}

// saveSessionMetadata saves session metadata to disk
func (sm *SessionManager) saveSessionMetadata(session *Session) error {
	metadata := SessionMetadata{
		ID:        session.ID,
		AccountID: session.AccountID,
		Region:    session.Region,
		StartedAt: session.StartedAt,
		EndedAt:   session.EndedAt,
		Skills:    session.Skills,
		RiskScore: session.RiskScore,
	}

	metadataPath := filepath.Join(session.Path, "session.json")
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(metadataPath, data, 0644)
}

// SaveEvidence saves evidence data to disk
func (sm *SessionManager) SaveEvidence(sessionID, skillName string, data interface{}) error {
	sessionPath := filepath.Join(sm.basePath, sessionID)
	evidencePath := filepath.Join(sessionPath, "evidence", skillName)

	// Create directory if needed
	if err := os.MkdirAll(evidencePath, 0755); err != nil {
		return fmt.Errorf("failed to create evidence directory: %w", err)
	}

	// Save evidence data
	filePath := filepath.Join(evidencePath, "raw-data.json")
	dataJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, dataJSON, 0644)
}

// SaveFinding saves finding data to disk
func (sm *SessionManager) SaveFinding(sessionID, skillName string, data interface{}) error {
	sessionPath := filepath.Join(sm.basePath, sessionID)
	findingsPath := filepath.Join(sessionPath, "findings")

	// Create directory if needed
	if err := os.MkdirAll(findingsPath, 0755); err != nil {
		return fmt.Errorf("failed to create findings directory: %w", err)
	}

	// Save findings data
	filePath := filepath.Join(findingsPath, fmt.Sprintf("%s.json", skillName))
	dataJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, dataJSON, 0644)
}

// SaveReport saves report to disk
func (sm *SessionManager) SaveReport(sessionID, reportName, content string) error {
	sessionPath := filepath.Join(sm.basePath, sessionID)
	reportsPath := filepath.Join(sessionPath, "reports")

	// Create directory if needed
	if err := os.MkdirAll(reportsPath, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Save report
	filePath := filepath.Join(reportsPath, reportName)
	return os.WriteFile(filePath, []byte(content), 0644)
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	sessionPath := filepath.Join(sm.basePath, sessionID)

	// Check if session exists
	if _, err := os.Stat(sessionPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Read metadata
	metadataPath := filepath.Join(sessionPath, "session.json")
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read session metadata: %w", err)
	}

	var metadata SessionMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse session metadata: %w", err)
	}

	return &Session{
		ID:        metadata.ID,
		Path:      sessionPath,
		AccountID: metadata.AccountID,
		Region:    metadata.Region,
		StartedAt: metadata.StartedAt,
		EndedAt:   metadata.EndedAt,
		Skills:    metadata.Skills,
		RiskScore: metadata.RiskScore,
	}, nil
}

// ListSessions lists all available sessions
func (sm *SessionManager) ListSessions() ([]Session, error) {
	var sessions []Session

	entries, err := os.ReadDir(sm.basePath)
	if err != nil {
		if os.IsNotExist(err) {
			return sessions, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			session, err := sm.GetSession(entry.Name())
			if err == nil {
				sessions = append(sessions, *session)
			}
		}
	}

	return sessions, nil
}
