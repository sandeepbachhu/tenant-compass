# AWS Organization Account Metadata Collection Script

## Overview

This Python script (`ec2_tc_script_save_local.py`) is designed to collect metadata from AWS Organization accounts and their member accounts. It performs the following operations:

1. Scans a DynamoDB table to identify active AWS Cloud Usage tenants
2. For each organization account:
   - Assumes a cross-account IAM role to access the organization
   - Retrieves organization information and all member accounts
   - Collects metadata for each account (ID, name, org ID, tags, etc.)
   - Creates a CSV report with this information
   - Uploads the report to an S3 bucket
   - Optionally saves a local copy

The script is intended to run on an EC2 instance or locally, and it uses environment variables for configuration.

## Prerequisites

### Environment Variables

The script requires the following environment variables to be set in a `.env` file:

```
OUTPUT_BUCKET=your-s3-bucket-name
DYNAMO_TABLE_NAME=your-dynamodb-table-name
CROSS_ACCOUNT_ROLE_NAME=your-cross-account-role-name
```

### Python Dependencies

Install the required Python packages:

```bash
pip install boto3 python-dotenv
```

### AWS IAM Permissions

#### For the EC2 Instance or Local Execution Role

The IAM role or user running the script needs the following permissions:

1. **DynamoDB Permissions**:
   - `dynamodb:Scan` on the specified DynamoDB table

2. **STS Permissions**:
   - `sts:AssumeRole` to assume the cross-account role in organization accounts

3. **S3 Permissions**:
   - `s3:PutObject` on the specified S3 bucket

Example IAM Policy:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:Scan"
            ],
            "Resource": "arn:aws:dynamodb:us-east-1:*:table/YOUR_DYNAMO_TABLE_NAME"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": "arn:aws:iam::*:role/YOUR_CROSS_ACCOUNT_ROLE_NAME"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::YOUR_S3_BUCKET_NAME/*"
        }
    ]
}
```

#### For the Cross-Account Role in Each Organization Account

Each organization account must have a role with the name specified in `CROSS_ACCOUNT_ROLE_NAME` that has the following permissions:

1. **Organizations Permissions**:
   - `organizations:DescribeOrganization`
   - `organizations:ListAccounts`
   - `organizations:ListTagsForResource`

2. **STS Permissions**:
   - `sts:GetCallerIdentity`

3. **Account Permissions**:
   - `account:GetRegions`

Example IAM Policy for the Cross-Account Role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
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
                "sts:GetCallerIdentity",
                "account:GetRegions"
            ],
            "Resource": "*"
        }
    ]
}
```

### Trust Policy for Cross-Account Role

Each organization account must have a trust policy that allows the EC2 instance or local execution role to assume the cross-account role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::ACCOUNT_ID_RUNNING_SCRIPT:role/ROLE_NAME_RUNNING_SCRIPT"
            },
            "Action": "sts:AssumeRole",
            "Condition": {}
        }
    ]
}
```

Replace `ACCOUNT_ID_RUNNING_SCRIPT` with the AWS account ID where the script is running, and `ROLE_NAME_RUNNING_SCRIPT` with the role name that is executing the script.

## Execution

Run the script using Python:

```bash
python ec2_tc_script_save_local.py
```

By default, the script will:
1. Save CSV reports to the specified S3 bucket
2. Save local copies of the reports to `~/aws-org-scripts-outputs/`

## Script Workflow

The script follows this workflow:

1. Loads environment variables from a `.env` file
2. Connects to DynamoDB and scans for active AWS Cloud Usage tenants
3. For each organization account found:
   - Assumes the cross-account role in the organization account
   - Retrieves organization information
   - Lists all member accounts in the organization
   - Collects metadata for each account, including:
     - Account ID
     - Account Name
     - Organization ID
     - Tenant Name (Management Account ID)
     - Cloud Service Provider (AWS)
     - Account Status
     - Environment tag (if available)
     - Aide-ID tag (if available)
   - Creates a CSV report with the collected metadata
   - Uploads the CSV to the specified S3 bucket
   - Optionally saves a local copy of the CSV

## Flow Diagram

```mermaid
graph TD
    A[Script Start] --> B[Load Environment Variables]
    B --> C[Connect to DynamoDB]
    C --> D[Scan for Active AWS Cloud Usage Tenants]
    D --> E[For Each Organization Account]
    E --> F[Assume Cross-Account Role]
    F --> G[Retrieve Organization Info]
    G --> H[List Member Accounts]
    H --> I[Collect Account Metadata]
    I --> J[Generate CSV Report]
    J --> K[Upload to S3 Bucket]
    K --> L[Save Local Copy if Enabled]
    L --> M[Process Next Organization Account]
    M -->|More accounts| E
    M -->|No more accounts| N[Script End]
```

## Output Format

The script generates CSV files with the following naming convention:

```
aws-{org_account_id}-account-metadata-report-{timestamp}.csv
```

Each CSV contains the following columns:
- Account_Id
- Account_Name
- Org_ID
- Tenant_Name
- CSP
- Billing_Account_State
- Region_Group
- Tenant_ID
- Environment
- Aide_ID

## Troubleshooting

Common issues and their solutions:

1. **Missing Environment Variables**: Ensure all required environment variables are set in the `.env` file.
2. **IAM Permission Issues**: Verify that the IAM roles have the correct permissions as described in the Prerequisites section.
3. **Cross-Account Role Not Found**: Ensure the cross-account role exists in each organization account with the correct name and trust policy.
4. **S3 Bucket Access Denied**: Verify that the script has permission to upload objects to the specified S3 bucket.
