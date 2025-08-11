#!/usr/bin/env python3
import requests
import boto3
import json
import argparse
import os
from datetime import datetime
from botocore.exceptions import ClientError

def get_secret_from_aws_secrets_manager(secret_name, region_name='us-east-1'):
    """
    Retrieve a secret from AWS Secrets Manager.
    
    Args:
        secret_name (str): Name of the secret in AWS Secrets Manager
        region_name (str): AWS region where the secret is stored
        
    Returns:
        str: The secret value
    """
    try:
        # Create a Secrets Manager client
        session = boto3.session.Session()
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )
        
        # Retrieve the secret value
        response = client.get_secret_value(SecretId=secret_name)
        
        # Parse the secret value
        if 'SecretString' in response:
            secret = response['SecretString']
            # If it's a JSON string, parse it and return the specific key
            try:
                secret_dict = json.loads(secret)
                # If it's a JSON object, return the first value or look for common keys
                if isinstance(secret_dict, dict):
                    # Look for common key names for client secret
                    for key in ['client_secret', 'AZURE_CLIENT_SECRET', 'secret', 'value']:
                        if key in secret_dict:
                            return secret_dict[key]
                    # If no common key found, return the first value
                    return list(secret_dict.values())[0] if secret_dict else secret
                return secret
            except json.JSONDecodeError:
                # If it's not JSON, return as plain text
                return secret
        else:
            # Handle binary secrets (though unlikely for client secrets)
            return response['SecretBinary'].decode('utf-8')
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'DecryptionFailureException':
            raise Exception(f"Secrets Manager can't decrypt the protected secret text using the provided KMS key: {str(e)}")
        elif error_code == 'InternalServiceErrorException':
            raise Exception(f"An error occurred on the server side: {str(e)}")
        elif error_code == 'InvalidParameterException':
            raise Exception(f"Invalid parameter provided: {str(e)}")
        elif error_code == 'InvalidRequestException':
            raise Exception(f"Invalid request: {str(e)}")
        elif error_code == 'ResourceNotFoundException':
            raise Exception(f"Secret '{secret_name}' not found in AWS Secrets Manager: {str(e)}")
        else:
            raise Exception(f"Error retrieving secret from AWS Secrets Manager: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error retrieving secret from AWS Secrets Manager: {str(e)}")

def get_oidc_credentials(account_id=None, role_name=None, tenant_id=None, client_id=None, client_secret=None, secret_name=None, secret_region='us-east-1'):
    """
    Get AWS credentials using OIDC authentication with Azure AD.
    
    Args:
        account_id (str): AWS account ID
        role_name (str): Name of the IAM role to assume
        tenant_id (str): Azure AD tenant ID
        client_id (str): Azure AD client ID
        client_secret (str): Azure AD client secret (optional if using secret_name)
        secret_name (str): Name of the secret in AWS Secrets Manager containing the client secret
        secret_region (str): AWS region where the secret is stored (default: us-east-1)
        
    Returns:
        dict: AWS credentials
    """
    # Default values (can be overridden by environment variables or arguments)
    account_id = account_id or os.environ.get('AWS_ACCOUNT_ID')
    role_name = role_name or os.environ.get('AWS_ROLE_NAME')
    tenant_id = tenant_id or os.environ.get('AZURE_TENANT_ID')
    client_id = client_id or os.environ.get('AZURE_CLIENT_ID')
    
    # Get client secret from AWS Secrets Manager if secret_name is provided, otherwise use environment variable
    if not client_secret:
        secret_name = secret_name or os.environ.get('AZURE_CLIENT_SECRET_NAME')
        if secret_name:
            try:
                client_secret = get_secret_from_aws_secrets_manager(secret_name, secret_region)
                print(f"Successfully retrieved AZURE_CLIENT_SECRET from AWS Secrets Manager: {secret_name}")
            except Exception as e:
                print(f"Warning: Failed to retrieve secret from AWS Secrets Manager: {e}")
                # Fallback to environment variable
                client_secret = os.environ.get('AZURE_CLIENT_SECRET')
        else:
            # Fallback to environment variable if no secret name provided
            client_secret = os.environ.get('AZURE_CLIENT_SECRET')
    
    # Validate required parameters
    if not all([account_id, role_name, tenant_id, client_id, client_secret]):
        missing = []
        if not account_id: missing.append("AWS_ACCOUNT_ID")
        if not role_name: missing.append("AWS_ROLE_NAME")
        if not tenant_id: missing.append("AZURE_TENANT_ID")
        if not client_id: missing.append("AZURE_CLIENT_ID")
        if not client_secret: missing.append("AZURE_CLIENT_SECRET")
        raise ValueError(f"Missing required parameters: {', '.join(missing)}")
    
    # Step 1: Get access token from Azure AD
    audience = "api://azure-oidc-aws/.default"
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    
    token_data = {
        "client_id": client_id,
        "scope": audience,
        "client_secret": client_secret,
        "grant_type": "client_credentials"
    }
    
    try:
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")
        
        if not access_token:
            raise ValueError("Failed to retrieve access token")
            
    except Exception as e:
        raise Exception(f"Error getting access token: {str(e)}")
    
    # Step 2: Assume role with web identity
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    session_name = "AWSAssumeRole"
    
    try:
        sts_client = boto3.client('sts')
        response = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=access_token
        )
        
        credentials = response['Credentials']
        
        # Format the output to match the credentials.sh script
        result = {
            "Version": 1,
            "AccessKeyId": credentials['AccessKeyId'],
            "SecretAccessKey": credentials['SecretAccessKey'],
            "SessionToken": credentials['SessionToken'],
            "Expiration": credentials['Expiration'].isoformat()
        }
        
        return result
        
    except Exception as e:
        raise Exception(f"Error assuming role: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description='Get AWS credentials using OIDC authentication with Azure AD')
    parser.add_argument('--account-id', help='AWS account ID')
    parser.add_argument('--role-name', help='Name of the IAM role to assume')
    parser.add_argument('--tenant-id', help='Azure AD tenant ID')
    parser.add_argument('--client-id', help='Azure AD client ID')
    parser.add_argument('--client-secret', help='Azure AD client secret')
    parser.add_argument('--secret-name', help='Name of the secret in AWS Secrets Manager containing the client secret')
    parser.add_argument('--secret-region', default='us-east-1', help='AWS region where the secret is stored (default: us-east-1)')
    
    args = parser.parse_args()
    
    try:
        credentials = get_oidc_credentials(
            account_id=args.account_id,
            role_name=args.role_name,
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            client_secret=args.client_secret,
            secret_name=args.secret_name,
            secret_region=args.secret_region
        )
        
        # Print the credentials as JSON (same format as credentials.sh)
        print(json.dumps(credentials, indent=2))
        
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

#python3 credentials.py --account-id {} --role-name {} --tenant-id {} --client-id {} --client-secret {}
