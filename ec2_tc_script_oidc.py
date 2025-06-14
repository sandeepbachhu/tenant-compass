import boto3
import os
import json
import datetime
import csv
import io
import pathlib
import sys
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr
from credentials import get_oidc_credentials

# Load environment variables from .env file (for EC2/local use)
load_dotenv()

REGION = 'us-east-1'
S3_BUCKET = os.getenv('OUTPUT_BUCKET')
DYNAMO_TABLE_NAME = os.getenv('DYNAMO_TABLE_NAME')
ROLE_NAME = os.getenv('CROSS_ACCOUNT_ROLE_NAME')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
SAVE_LOCAL = True

US_REGIONS = {
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'us-gov-west-1', 'us-gov-east-1'
}

OUTPUT_DIR = pathlib.Path.home() / "aws-org-scripts-outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def assume_role_with_oidc(account_id, role_name, session_name="OIDCSession"):
    """
    Assume a role in the specified AWS account using OIDC authentication.
    
    Args:
        account_id (str): AWS account ID
        role_name (str): Name of the IAM role to assume
        session_name (str): Name for the role session
        
    Returns:
        boto3.Session: A boto3 session with the assumed role credentials
    """
    try:
        # Get credentials using OIDC authentication
        credentials = get_oidc_credentials(
            account_id=account_id,
            role_name=role_name,
            tenant_id=AZURE_TENANT_ID,
            client_id=AZURE_CLIENT_ID,
            client_secret=AZURE_CLIENT_SECRET
        )
        
        # Create a boto3 session with the credentials
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=REGION
        )
        
        return session
        
    except Exception as e:
        raise Exception(f"Error assuming role with OIDC for account {account_id}: {str(e)}")

def main():
    # Validate required environment variables
    required_vars = ['OUTPUT_BUCKET', 'DYNAMO_TABLE_NAME', 'CROSS_ACCOUNT_ROLE_NAME', 
                     'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"❌ Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file or environment.")
        sys.exit(1)

    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    table = dynamodb.Table(DYNAMO_TABLE_NAME)

    try:
        tenant_ids = []
        scan_kwargs = {
            'FilterExpression': Attr('tenant_type').eq('Cloud Usage') & Attr('tenant_status').eq('Active') & Attr('cloud_service_provider').eq('AWS')
        }

        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        tenant_ids.extend(item['tenant_id'] for item in items)

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **scan_kwargs)
            items = response.get('Items', [])
            tenant_ids.extend(item['tenant_id'] for item in items)

        print(f"✅ Total active Cloud Usage tenant accounts found: {len(tenant_ids)}")
        print("Tenant IDs:", tenant_ids)

    except Exception as e:
        print(f"❌ Error scanning DynamoDB table: {e}")
        return

    s3 = boto3.client('s3', region_name=REGION)
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')

    for org_account_id in tenant_ids:
        try:
            print(f"\n➡️ Processing Org account: {org_account_id}")
            # Use OIDC authentication instead of direct role assumption
            session = assume_role_with_oidc(org_account_id, ROLE_NAME)
            org_client = session.client('organizations', region_name=REGION)
            identity_client = session.client('sts', region_name=REGION)
            region_client = session.client('account', region_name=REGION)
            tagging_client = session.client('resourcegroupstaggingapi', region_name=REGION)

            org_info = org_client.describe_organization()['Organization']
            if org_info['MasterAccountId'] != org_account_id:
                print(f"⏭️ Skipping {org_account_id}: Not a management account.")
                continue

            member_accounts = []
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                print(f"🔄 Fetched {len(page['Accounts'])} accounts from paginator")
                member_accounts.extend(page['Accounts'])

            print(f"📋 Total member accounts in org {org_account_id}: {len(member_accounts)}")

            all_account_data = []
            for account in member_accounts:
                account_id = account['Id']
                account_name = account['Name']
                account_status = account['Status']

                env_value = ''
                aide_id_value = ''
                try:
                    tags_response = org_client.list_tags_for_resource(ResourceId=account_id)
                    tags = {tag['Key'].lower(): tag['Value'] for tag in tags_response.get('Tags', [])}
                    env_value = tags.get('environment', '')
                    aide_id_value = tags.get('aide-id', '')
                except Exception as e:
                    print(f"⚠️ Warning: Could not fetch tags for account {account_id}: {e}")

                all_account_data.append({
                    "Account_Id": account_id,
                    "Account_Name": account_name,
                    "Org_ID": org_info['Id'],
                    "Tenant_Name": org_info['MasterAccountId'],
                    "CSP": "AWS",
                    "Billing_Account_State": account_status,
                    "Region_Group": '',
                    "Tenant_ID": org_info['MasterAccountId'],
                    "Environment": env_value,
                    "Aide_ID": aide_id_value
                })

            if not all_account_data:
                print(f"❌ No member accounts found for Org {org_account_id}.")
                continue

            all_account_data.sort(key=lambda x: x['Account_Id'] != org_account_id)

            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=all_account_data[0].keys())
            writer.writeheader()
            for row in all_account_data:
                writer.writerow(row)

            csv_key = f"aws-{org_account_id}-account-metadata-report-{timestamp}.csv"
            s3.put_object(Bucket=S3_BUCKET, Key=csv_key, Body=output.getvalue())
            print(f"✅ Uploaded metadata for Org {org_account_id} to S3: {csv_key}")

            if SAVE_LOCAL:
                local_path = OUTPUT_DIR / csv_key
                with open(local_path, 'w') as f:
                    f.write(output.getvalue())
                print(f"📁 Saved local backup at: {local_path}")

        except Exception as e:
            print(f"❌ Skipping Org account {org_account_id} due to error: {e}")

if __name__ == '__main__':
    main()
