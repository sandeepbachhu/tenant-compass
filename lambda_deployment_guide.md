# Lambda Tags Test Function - Deployment Guide

## Overview

This Lambda function tests the Resource Groups Tagging API across your AWS organization to help identify VPC and resource distribution issues. It's designed for testing in your local AWS organization account without dependencies on DynamoDB or OIDC authentication.

## Files Created

1. **`lambda_tags_test.py`** - Main Lambda function code
2. **`lambda_deployment_guide.md`** - This deployment guide

## Prerequisites

### 1. AWS Organization Setup
- Your AWS account must be part of an AWS Organization
- The Lambda will be deployed in the management account or an account with organization access

### 2. Cross-Account Roles
Each member account in your organization needs a role that the Lambda can assume:

**Default Role Name**: `OrganizationAccountAccessRole` (AWS default)
**Alternative**: You can specify a custom role name via environment variable

## Deployment Steps

### Step 1: Create S3 Bucket
Create an S3 bucket to store the CSV reports:

```bash
aws s3 mb s3://your-lambda-tags-test-bucket
```

### Step 2: Create Lambda Execution Role

Create an IAM role for the Lambda with the following permissions:

**Trust Policy**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

**IAM Policy**:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "organizations:DescribeOrganization",
                "organizations:ListAccounts",
                "organizations:ListTagsForResource"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::your-lambda-tags-test-bucket/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "resourcegroupstaggingapi:GetResources"
            ],
            "Resource": "*"
        }
    ]
}
```

### Step 3: Create Lambda Function

1. **Package the function**:
   ```bash
   zip lambda_tags_test.zip lambda_tags_test.py
   ```

2. **Create the Lambda function**:
   ```bash
   aws lambda create-function \
     --function-name lambda-tags-test \
     --runtime python3.9 \
     --role arn:aws:iam::YOUR-ACCOUNT-ID:role/lambda-tags-test-role \
     --handler lambda_tags_test.lambda_handler \
     --zip-file fileb://lambda_tags_test.zip \
     --timeout 900 \
     --memory-size 512
   ```

### Step 4: Set Environment Variables

```bash
aws lambda update-function-configuration \
  --function-name lambda-tags-test \
  --environment Variables='{
    "S3_BUCKET":"your-lambda-tags-test-bucket",
    "CROSS_ACCOUNT_ROLE_NAME":"OrganizationAccountAccessRole"
  }'
```

### Step 5: Test the Function

```bash
aws lambda invoke \
  --function-name lambda-tags-test \
  --payload '{}' \
  response.json

cat response.json
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `S3_BUCKET` | Yes | None | S3 bucket name for storing CSV reports |
| `CROSS_ACCOUNT_ROLE_NAME` | No | `OrganizationAccountAccessRole` | IAM role name to assume in member accounts |

## Expected Output

### Lambda Logs
```
🚀 Starting Lambda Tags API Test
📦 Using S3 bucket: your-lambda-tags-test-bucket
🔑 Using cross-account role: OrganizationAccountAccessRole
🏢 Getting organization information...
   Organization ID: o-1234567890
   Management Account: 123456789012
👥 Discovering organization accounts...
   Found 5 accounts in organization

🔍 Processing account: 123456789012 (Management Account)
   🏠 Using management account session
   🔍 Scanning tagged resources in account 123456789012...
   📊 Found 1322 tagged resources
   🌍 Regions: {'global': 168, 'us-east-1': 1154}
   🔧 Services: {'ec2': 556, 'lambda': 65, 's3': 6}
   🏗️  EC2 Types: {'vpc': 2, 'subnet': 8, 'security-group': 6}
   🌍 Active regions: ['us-east-1']
   🏷️  Region group: US, Regions: us-east-1

🔍 Processing account: 234567890123 (Member Account 1)
   🔄 Assuming role OrganizationAccountAccessRole in member account
   🔍 Scanning tagged resources in account 234567890123...
   📊 Found 45 tagged resources
   🌍 Regions: {'us-west-2': 45}
   🔧 Services: {'ec2': 30, 'rds': 15}
   🏗️  EC2 Types: {'vpc': 1, 'subnet': 4, 'instance': 25}
   🌍 Active regions: ['us-west-2']
   🏷️  Region group: US, Regions: us-west-2

📄 Generating CSV report with 5 accounts...
📤 Uploading report to S3: lambda-tags-test-o-1234567890-2025-07-21T15-45-30Z.csv
✅ Lambda execution completed successfully!
```

### CSV Report
The function generates a CSV file with columns:
- Account_ID
- Account_Name  
- Org_ID
- Tenant_Name
- CSP
- Billing_Account_State
- Region_Group
- Regions
- Tenant_ID
- Environment
- Resource_Summary (JSON with detailed resource breakdown)

## Troubleshooting

### Common Issues

1. **"Access Denied" when assuming roles**
   - Ensure `OrganizationAccountAccessRole` exists in all member accounts
   - Verify the role trusts the Lambda execution role
   - Check that the role has `tag:GetResources` permission

2. **"S3 Access Denied"**
   - Verify the S3 bucket exists
   - Check that the Lambda execution role has `s3:PutObject` permission
   - Ensure the bucket policy allows the Lambda role

3. **"No organization found"**
   - Ensure the Lambda is running in an account that's part of an AWS Organization
   - Verify the Lambda execution role has `organizations:DescribeOrganization` permission

4. **Timeout errors**
   - Increase Lambda timeout (current: 15 minutes)
   - Consider processing fewer accounts per invocation for large organizations

### Debugging

Enable detailed logging by checking CloudWatch Logs for the Lambda function. The function provides extensive logging to help identify issues with:
- Organization discovery
- Cross-account role assumption
- Resource scanning
- S3 upload

## Testing VPC Detection

This Lambda function will help you test:

1. **VPC Discovery**: Check if VPCs appear in the EC2 Types breakdown
2. **Regional Distribution**: See which regions have tagged resources
3. **Cross-Account Access**: Verify role assumption works across accounts
4. **Resource Tagging**: Identify which resources have tags vs. untagged resources

The detailed logging will show exactly what resources are found in each account and region, helping you identify why certain VPCs or regions might not be detected in your main script.
