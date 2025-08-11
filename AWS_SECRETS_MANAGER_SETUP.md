# AWS Secrets Manager Integration for AZURE_CLIENT_SECRET

This document explains how to use AWS Secrets Manager to store the `AZURE_CLIENT_SECRET` instead of using environment variables.

## Overview

The code has been modified to support reading the `AZURE_CLIENT_SECRET` from AWS Secrets Manager instead of environment variables. This provides better security by:

- Centralizing secret management
- Enabling secret rotation
- Providing audit trails
- Encrypting secrets at rest and in transit

## Setup Instructions

### 1. Store the Secret in AWS Secrets Manager

You can store the secret in AWS Secrets Manager using either the AWS CLI or AWS Console.

#### Option A: Using AWS CLI

```bash
# Store as plain text secret
aws secretsmanager create-secret \
    --name "azure-client-secret" \
    --description "Azure AD Client Secret for OIDC authentication" \
    --secret-string "your-actual-client-secret-value" \
    --region us-east-1

# Or store as JSON (if you want to store multiple values)
aws secretsmanager create-secret \
    --name "azure-oidc-credentials" \
    --description "Azure AD credentials for OIDC authentication" \
    --secret-string '{"client_secret":"your-actual-client-secret-value","other_field":"other_value"}' \
    --region us-east-1
```

#### Option B: Using AWS Console

1. Go to AWS Secrets Manager in the AWS Console
2. Click "Store a new secret"
3. Choose "Other type of secret"
4. Enter your secret as either:
   - **Plain text**: Just paste your client secret value
   - **Key/value pairs**: Use key `client_secret` with your secret as the value
5. Give it a name like `azure-client-secret`
6. Complete the setup

### 2. Configure Environment Variables

Update your `.env` file or environment variables:

```bash
# Required: Name of the secret in AWS Secrets Manager
AZURE_CLIENT_SECRET_NAME=azure-client-secret

# Optional: Region where the secret is stored (defaults to us-east-1)
AZURE_CLIENT_SECRET_REGION=us-east-1

# Remove or comment out the old environment variable
# AZURE_CLIENT_SECRET=your-old-secret-value
```

### 3. IAM Permissions

Ensure your execution role has the necessary permissions to read from Secrets Manager:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue"
            ],
            "Resource": "arn:aws:secretsmanager:us-east-1:*:secret:azure-client-secret*"
        }
    ]
}
```

## Usage

### Environment Variables

The code now supports these environment variables:

- `AZURE_CLIENT_SECRET_NAME`: Name of the secret in AWS Secrets Manager
- `AZURE_CLIENT_SECRET_REGION`: AWS region where the secret is stored (default: us-east-1)
- `AZURE_CLIENT_SECRET`: Fallback to direct environment variable (for backward compatibility)

### Priority Order

The code will attempt to get the client secret in this order:

1. If `AZURE_CLIENT_SECRET_NAME` is set, retrieve from AWS Secrets Manager
2. If that fails, fall back to `AZURE_CLIENT_SECRET` environment variable
3. If neither is available, the script will exit with an error

### Command Line Usage

The `credentials.py` script also supports command line arguments:

```bash
# Using AWS Secrets Manager
python3 credentials.py \
    --account-id 123456789012 \
    --role-name MyRole \
    --tenant-id your-tenant-id \
    --client-id your-client-id \
    --secret-name azure-client-secret \
    --secret-region us-east-1

# Using direct client secret (fallback)
python3 credentials.py \
    --account-id 123456789012 \
    --role-name MyRole \
    --tenant-id your-tenant-id \
    --client-id your-client-id \
    --client-secret your-direct-secret
```

## Secret Format Support

The code supports multiple secret formats in AWS Secrets Manager:

### Plain Text
```
your-client-secret-value
```

### JSON with specific keys
```json
{
    "client_secret": "your-client-secret-value"
}
```

```json
{
    "AZURE_CLIENT_SECRET": "your-client-secret-value"
}
```

```json
{
    "secret": "your-client-secret-value"
}
```

```json
{
    "value": "your-client-secret-value"
}
```

The code will automatically detect the format and extract the appropriate value.

## Error Handling

- If the secret is not found, the code will fall back to environment variables
- If neither the secret nor environment variable is available, the script will exit with a clear error message
- All AWS Secrets Manager errors are caught and logged with descriptive messages

## Security Benefits

1. **Centralized Management**: All secrets in one place
2. **Encryption**: Secrets are encrypted at rest and in transit
3. **Access Control**: Fine-grained IAM permissions
4. **Audit Trail**: All secret access is logged in CloudTrail
5. **Rotation**: Supports automatic secret rotation
6. **No Plain Text**: Secrets are not stored in code or environment files

## Migration from Environment Variables

To migrate from environment variables to AWS Secrets Manager:

1. Store your current `AZURE_CLIENT_SECRET` value in AWS Secrets Manager
2. Set `AZURE_CLIENT_SECRET_NAME` environment variable
3. Remove or comment out `AZURE_CLIENT_SECRET` from your `.env` file
4. Test the application to ensure it works
5. Update your deployment scripts/configurations

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure your IAM role has `secretsmanager:GetSecretValue` permission
2. **Secret Not Found**: Verify the secret name and region are correct
3. **Invalid JSON**: If using JSON format, ensure it's valid JSON
4. **Region Mismatch**: Ensure the secret region matches your configuration

### Debug Information

The script will print helpful information:
- Whether it's using AWS Secrets Manager or environment variables
- The secret name and region being used
- Success/failure messages for secret retrieval

## Example Output

```
Using AWS Secrets Manager for AZURE_CLIENT_SECRET: azure-client-secret (region: us-east-1)
Successfully retrieved AZURE_CLIENT_SECRET from AWS Secrets Manager: azure-client-secret
```

Or for fallback:
```
Using environment variable for AZURE_CLIENT_SECRET
Warning: Failed to retrieve secret from AWS Secrets Manager: Secret 'azure-client-secret' not found
