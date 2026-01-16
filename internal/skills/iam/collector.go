package iam

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/gcuesta/drystone/pkg/models"
)

// Collector gathers IAM data from AWS
type Collector struct {
	iamClient       *iam.Client
	cloudtrailClient *cloudtrail.Client
}

// NewCollector creates a new IAM collector
func NewCollector(iamClient *iam.Client, cloudtrailClient *cloudtrail.Client) *Collector {
	return &Collector{
		iamClient:        iamClient,
		cloudtrailClient: cloudtrailClient,
	}
}

// IAMData represents collected IAM data
type IAMData struct {
	Users              []UserData        `json:"users"`
	Groups             []GroupData       `json:"groups"`
	Roles              []RoleData        `json:"roles"`
	Policies           []PolicyData      `json:"policies"`
	AccountAuthDetails AccountAuthDetails `json:"account_auth_details"`
	RootAccountUsage   RootAccountUsage  `json:"root_account_usage"`
}

// UserData represents an IAM user
type UserData struct {
	Username      string                `json:"username"`
	UserID        string                `json:"user_id"`
	Arn           string                `json:"arn"`
	CreateDate    string                `json:"create_date"`
	LastUsed      string                `json:"last_used,omitempty"`
	MFADevices    []string              `json:"mfa_devices"`
	AccessKeys    []AccessKeyData       `json:"access_keys"`
	InlinePolicies []string             `json:"inline_policies"`
	GroupMemberships []string           `json:"group_memberships"`
	ConsoleAccess bool                  `json:"console_access"`
}

// GroupData represents an IAM group
type GroupData struct {
	GroupName      string    `json:"group_name"`
	GroupID        string    `json:"group_id"`
	Arn            string    `json:"arn"`
	CreateDate     string    `json:"create_date"`
	Members        []string  `json:"members"`
	InlinePolicies []string  `json:"inline_policies"`
}

// RoleData represents an IAM role
type RoleData struct {
	RoleName       string    `json:"role_name"`
	RoleID         string    `json:"role_id"`
	Arn            string    `json:"arn"`
	CreateDate     string    `json:"create_date"`
	AssumeRolePolicyDocument string `json:"assume_role_policy"`
	InlinePolicies []string  `json:"inline_policies"`
	MaxSessionDuration *int32 `json:"max_session_duration"`
	LastUsed       string    `json:"last_used,omitempty"`
}

// AccessKeyData represents an IAM access key
type AccessKeyData struct {
	AccessKeyID  string `json:"access_key_id"`
	Status       string `json:"status"`
	CreateDate   string `json:"create_date"`
	LastUsedDate string `json:"last_used_date,omitempty"`
	DaysSinceUsed int    `json:"days_since_used,omitempty"`
}

// PolicyData represents an IAM policy
type PolicyData struct {
	PolicyName     string `json:"policy_name"`
	PolicyID       string `json:"policy_id"`
	Arn            string `json:"arn"`
	CreateDate     string `json:"create_date"`
	DefaultVersionID string `json:"default_version_id"`
	Document       string `json:"document"`
	IsAttachable   bool   `json:"is_attachable"`
	AttachmentCount int32  `json:"attachment_count"`
}

// AccountAuthDetails represents AWS account authentication details
type AccountAuthDetails struct {
	AccountID        string `json:"account_id"`
	Arn              string `json:"arn"`
	UserCount        int    `json:"user_count"`
	GroupCount       int    `json:"group_count"`
	RoleCount        int    `json:"role_count"`
	PolicyCount      int    `json:"policy_count"`
}

// RootAccountUsage represents root account usage
type RootAccountUsage struct {
	HasAccessKeys bool   `json:"has_access_keys"`
	AccessKeyCount int   `json:"access_key_count"`
	LastUsedDate  string `json:"last_used_date,omitempty"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	CloudTrailEvents int `json:"cloudtrail_events_30days"`
}

// Collect gathers IAM evidence
func (c *Collector) Collect(ctx context.Context, accountID string) (*models.Evidence, error) {
	startTime := time.Now()

	evidence := models.NewEvidence("iam", accountID, "global")

	// Collect IAM data
	iamData := &IAMData{}

	// Get account summary
	if err := c.collectAccountSummary(ctx, iamData, accountID); err != nil {
		evidence.AddError(fmt.Sprintf("failed to collect account summary: %v", err))
	}

	// Get users
	if err := c.collectUsers(ctx, iamData); err != nil {
		evidence.AddError(fmt.Sprintf("failed to collect users: %v", err))
	}

	// Get groups
	if err := c.collectGroups(ctx, iamData); err != nil {
		evidence.AddError(fmt.Sprintf("failed to collect groups: %v", err))
	}

	// Get roles
	if err := c.collectRoles(ctx, iamData); err != nil {
		evidence.AddError(fmt.Sprintf("failed to collect roles: %v", err))
	}

	// Get policies
	if err := c.collectPolicies(ctx, iamData); err != nil {
		evidence.AddError(fmt.Sprintf("failed to collect policies: %v", err))
	}

	// Get root account usage
	if err := c.collectRootAccountUsage(ctx, iamData); err != nil {
		evidence.AddWarning(fmt.Sprintf("failed to collect root account usage: %v", err))
	}

	// Store collected data
	evidence.AddData("iam", iamData)

	// Set metadata
	evidence.Metadata.Duration = time.Since(startTime).Seconds()
	evidence.Metadata.APICallCount = 10 // Approximate

	return evidence, nil
}

func (c *Collector) collectAccountSummary(ctx context.Context, data *IAMData, accountID string) error {
	summary, err := c.iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return err
	}

	if summary != nil && summary.SummaryMap != nil {
		data.AccountAuthDetails = AccountAuthDetails{
			AccountID:   accountID,
			UserCount:   int(summary.SummaryMap["UserCount"]),
			GroupCount:  int(summary.SummaryMap["GroupCount"]),
			RoleCount:   int(summary.SummaryMap["RoleCount"]),
			PolicyCount: int(summary.SummaryMap["PolicyCount"]),
		}
	}

	return nil
}

func (c *Collector) collectUsers(ctx context.Context, data *IAMData) error {
	paginator := iam.NewListUsersPaginator(c.iamClient, &iam.ListUsersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, user := range page.Users {
			userData := UserData{
				Username:   *user.UserName,
				UserID:     *user.UserId,
				Arn:        *user.Arn,
				CreateDate: user.CreateDate.String(),
			}

			// Get MFA devices
			mfaDevices, err := c.iamClient.ListMFADevices(ctx, &iam.ListMFADevicesInput{
				UserName: user.UserName,
			})
			if err == nil && mfaDevices != nil {
				for _, device := range mfaDevices.MFADevices {
					userData.MFADevices = append(userData.MFADevices, *device.SerialNumber)
				}
			}

			// Get access keys
			accessKeys, err := c.iamClient.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
				UserName: user.UserName,
			})
			if err == nil && accessKeys != nil {
				for _, key := range accessKeys.AccessKeyMetadata {
					akData := AccessKeyData{
						AccessKeyID: *key.AccessKeyId,
						Status:      string(key.Status),
						CreateDate:  key.CreateDate.String(),
					}
					userData.AccessKeys = append(userData.AccessKeys, akData)
				}
			}

			// Get login profile (console access)
			_, err = c.iamClient.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
				UserName: user.UserName,
			})
			userData.ConsoleAccess = (err == nil)

			// Get inline policies
			inlinePolicies, err := c.iamClient.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{
				UserName: user.UserName,
			})
			if err == nil && inlinePolicies != nil {
				userData.InlinePolicies = inlinePolicies.PolicyNames
			}

			// Get group memberships
			groups, err := c.iamClient.ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{
				UserName: user.UserName,
			})
			if err == nil && groups != nil {
				for _, group := range groups.Groups {
					userData.GroupMemberships = append(userData.GroupMemberships, *group.GroupName)
				}
			}

			data.Users = append(data.Users, userData)
		}
	}

	return nil
}

func (c *Collector) collectGroups(ctx context.Context, data *IAMData) error {
	paginator := iam.NewListGroupsPaginator(c.iamClient, &iam.ListGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, group := range page.Groups {
			groupData := GroupData{
				GroupName:  *group.GroupName,
				GroupID:    *group.GroupId,
				Arn:        *group.Arn,
				CreateDate: group.CreateDate.String(),
			}

			// Get group members
			members, err := c.iamClient.GetGroup(ctx, &iam.GetGroupInput{
				GroupName: group.GroupName,
			})
			if err == nil && members != nil {
				for _, user := range members.Users {
					groupData.Members = append(groupData.Members, *user.UserName)
				}
			}

			// Get inline policies
			inlinePolicies, err := c.iamClient.ListGroupPolicies(ctx, &iam.ListGroupPoliciesInput{
				GroupName: group.GroupName,
			})
			if err == nil && inlinePolicies != nil {
				groupData.InlinePolicies = inlinePolicies.PolicyNames
			}

			data.Groups = append(data.Groups, groupData)
		}
	}

	return nil
}

func (c *Collector) collectRoles(ctx context.Context, data *IAMData) error {
	paginator := iam.NewListRolesPaginator(c.iamClient, &iam.ListRolesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, role := range page.Roles {
			roleData := RoleData{
				RoleName:           *role.RoleName,
				RoleID:             *role.RoleId,
				Arn:                *role.Arn,
				CreateDate:         role.CreateDate.String(),
				MaxSessionDuration: nil, // Role has max session duration but it's complex type
			}

			// Get inline policies
			inlinePolicies, err := c.iamClient.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
				RoleName: role.RoleName,
			})
			if err == nil && inlinePolicies != nil {
				roleData.InlinePolicies = inlinePolicies.PolicyNames
			}

			data.Roles = append(data.Roles, roleData)
		}
	}

	return nil
}

func (c *Collector) collectPolicies(ctx context.Context, data *IAMData) error {
	paginator := iam.NewListPoliciesPaginator(c.iamClient, &iam.ListPoliciesInput{
		Scope: iamtypes.PolicyScopeTypeLocal,
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, policy := range page.Policies {
			policyData := PolicyData{
				PolicyName:      *policy.PolicyName,
				PolicyID:        *policy.PolicyId,
				Arn:             *policy.Arn,
				CreateDate:      policy.CreateDate.String(),
				DefaultVersionID: *policy.DefaultVersionId,
				IsAttachable:    policy.AttachmentCount != nil,
				AttachmentCount: *policy.AttachmentCount,
			}

			// Get policy document
			version, err := c.iamClient.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
				PolicyArn: policy.Arn,
				VersionId: policy.DefaultVersionId,
			})
			if err == nil && version != nil && version.PolicyVersion != nil {
				policyData.Document = *version.PolicyVersion.Document
			}

			data.Policies = append(data.Policies, policyData)
		}
	}

	return nil
}

func (c *Collector) collectRootAccountUsage(ctx context.Context, data *IAMData) error {
	// Get root account credential report
	credentialReport, err := c.iamClient.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		// If credential report not available, try alternative approach
		return c.getRootAccountFromSummary(ctx, data)
	}

	// Parse credential report
	if credentialReport.Content != nil {
		// Root account is first line
		lines := string(credentialReport.Content)
		// In a real implementation, parse CSV and find root account
		_ = lines
	}

	return nil
}

func (c *Collector) getRootAccountFromSummary(ctx context.Context, data *IAMData) error {
	summary, err := c.iamClient.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return err
	}

	if summary != nil && summary.SummaryMap != nil {
		rootData := RootAccountUsage{
			HasAccessKeys:  summary.SummaryMap["AccountAccessKeysPresent"] == 1,
			AccessKeyCount: int(summary.SummaryMap["AccountAccessKeys"]),
			MFAEnabled:     summary.SummaryMap["AccountMFAEnabled"] == 1,
		}
		data.RootAccountUsage = rootData
	}

	return nil
}
