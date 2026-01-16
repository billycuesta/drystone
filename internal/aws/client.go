package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// Client wraps AWS SDK clients
type Client struct {
	cfg              aws.Config
	iam              *iam.Client
	cloudtrail       *cloudtrail.Client
	sts              *sts.Client
	accountID        string
	region           string
}

// NewClient creates a new AWS client with the given profile and region
func NewClient(ctx context.Context, profile, region string) (*Client, error) {
	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(profile),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create service clients
	iamClient := iam.NewFromConfig(cfg)
	cloudtrailClient := cloudtrail.NewFromConfig(cfg)
	stsClient := sts.NewFromConfig(cfg)

	client := &Client{
		cfg:        cfg,
		iam:        iamClient,
		cloudtrail: cloudtrailClient,
		sts:        stsClient,
		region:     region,
	}

	// Get account ID
	if err := client.getAccountID(ctx); err != nil {
		return nil, err
	}

	return client, nil
}

// getAccountID retrieves the AWS account ID
func (c *Client) getAccountID(ctx context.Context) error {
	result, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return fmt.Errorf("account ID is nil")
	}

	c.accountID = *result.Account
	return nil
}

// GetAccountID returns the current AWS account ID
func (c *Client) GetAccountID(ctx context.Context) (string, error) {
	if c.accountID == "" {
		return "", fmt.Errorf("account ID not set")
	}
	return c.accountID, nil
}

// GetRegion returns the current AWS region
func (c *Client) GetRegion() string {
	return c.region
}

// IAM returns the IAM client
func (c *Client) IAM() *iam.Client {
	return c.iam
}

// CloudTrail returns the CloudTrail client
func (c *Client) CloudTrail() *cloudtrail.Client {
	return c.cloudtrail
}

// STS returns the STS client
func (c *Client) STS() *sts.Client {
	return c.sts
}

// ValidateCredentials validates that the AWS credentials are valid
func (c *Client) ValidateCredentials(ctx context.Context) error {
	result, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("invalid AWS credentials: %w", err)
	}

	// Log caller info
	fmt.Printf("✅ AWS Credentials Valid\n")
	fmt.Printf("   Account ID: %s\n", *result.Account)
	fmt.Printf("   ARN: %s\n", *result.Arn)
	fmt.Printf("   User ID: %s\n", *result.UserId)

	return nil
}

// GetAvailableRegions returns available AWS regions
func GetAvailableRegions() []string {
	return []string{
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-northeast-1",
		"ap-southeast-1",
		"ap-southeast-2",
	}
}

// GetAvailableProfiles returns available AWS profiles from config
func GetAvailableProfiles(ctx context.Context) ([]string, error) {
	// Load default config to get available profiles
	_, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}

	// For now, return default profiles
	// In a real implementation, parse ~/.aws/config
	return []string{"default"}, nil
}

// TestConnection tests the AWS connection
func (c *Client) TestConnection(ctx context.Context) (bool, error) {
	_, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	return err == nil, err
}

// AssumeRole assumes an IAM role
func (c *Client) AssumeRole(ctx context.Context, roleArn, sessionName string) (*ststypes.Credentials, error) {
	result, err := c.sts.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(sessionName),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to assume role: %w", err)
	}

	return result.Credentials, nil
}

// Close closes the AWS clients
func (c *Client) Close() error {
	// AWS SDK v2 doesn't require explicit close
	return nil
}
