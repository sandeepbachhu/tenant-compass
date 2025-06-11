#!/usr/bin/env python3
import requests
import boto3
import json
import argparse
import os
from datetime import datetime

def get_oidc_credentials(account_id=None, role_name=None, tenant_id=None, client_id=None, client_secret=None):
    """
    Get AWS credentials using OIDC authentication with Azure AD.
    
    Args:
        account_id (str): AWS account ID
        role_name (str): Name of the IAM role to assume
        tenant_id (str): Azure AD tenant ID
        client_id (str): Azure AD client ID
        client_secret (str): Azure AD client secret
        
    Returns:
        dict: AWS credentials
    """
    # Default values (can be overridden by environment variables or arguments)
    account_id = account_id or os.environ.get('AWS_ACCOUNT_ID')
    role_name = role_name or os.environ.get('AWS_ROLE_NAME')
    tenant_id = tenant_id or os.environ.get('AZURE_TENANT_ID')
    client_id = client_id or os.environ.get('AZURE_CLIENT_ID')
    client_secret = client_secret or os.environ.get('AZURE_CLIENT_SECRET')
    
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
    
    args = parser.parse_args()
    
    try:
        credentials = get_oidc_credentials(
            account_id=args.account_id,
            role_name=args.role_name,
            tenant_id=args.tenant_id,
            client_id=args.client_id,
            client_secret=args.client_secret
        )
        
        # Print the credentials as JSON (same format as credentials.sh)
        print(json.dumps(credentials, indent=2))
        
    except Exception as e:
        print(f"❌ Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

#python get_oidc_credentials.py --account-id YOUR_ACCOUNT_ID --role-name YOUR_ROLE_NAME --tenant-id YOUR_TENANT_ID --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
