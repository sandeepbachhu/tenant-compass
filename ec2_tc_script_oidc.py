import boto3
import os
import json
import datetime
import csv
import io
import pathlib
import sys
import re
import argparse
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr
from credentials import get_oidc_credentials

# Load environment variables from .env file (for EC2/local use)
load_dotenv()

REGION = 'us-east-1'
S3_BUCKET = os.getenv('OUTPUT_BUCKET')
DYNAMO_TABLE_NAME = os.getenv('DYNAMO_TABLE_NAME')
ROLE_NAME = os.getenv('CROSS_ACCOUNT_OIDC_ROLE_NAME')
AZURE_TENANT_ID = os.getenv('AZURE_TENANT_ID')
AZURE_CLIENT_ID = os.getenv('AZURE_CLIENT_ID')
AZURE_CLIENT_SECRET = os.getenv('AZURE_CLIENT_SECRET')
SAVE_LOCAL = True

# Region group mapping
REGION_GROUPS = {
    "US": {"us-east-1", "us-east-2", "us-west-1", "us-west-2"},
    "UK": {"eu-west-2"},
    "EU": {"eu-north-1", "eu-west-1"},
    "BR": {"sa-east-1"}
}

# Tag name variations for robust tag detection
ENVIRONMENT_TAG_VARIATIONS = ['environment', 'Environment', 'ENVIRONMENT', 'env', 'Env', 'ENV']
AIDE_ID_TAG_VARIATIONS = ['aide-id', 'AIDE_ID', 'AIDE-ID', 'aide_id', 'aideId', 'AideId']

OUTPUT_DIR = pathlib.Path.home() / "aws-org-scripts-outputs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def find_tag_value(tags_dict, tag_variations):
    """
    Find tag value by checking multiple tag name variations.
    
    Args:
        tags_dict (dict): Dictionary of tag key-value pairs
        tag_variations (list): List of tag name variations to check
        
    Returns:
        str: Tag value if found, empty string otherwise
    """
    for variation in tag_variations:
        if variation in tags_dict:
            return tags_dict[variation]
    return ''

def get_active_regions(tagging_client, account_id):
    """
    Get active regions for an account by querying tagged resources.
    
    Args:
        tagging_client: boto3 resourcegroupstaggingapi client
        account_id (str): AWS account ID
        
    Returns:
        list: Sorted list of active regions
    """
    active_regions = set()
    
    try:
        paginator = tagging_client.get_paginator('get_resources')
        
        for page in paginator.paginate(ResourcesPerPage=50):
            for resource in page.get('ResourceTagMappingList', []):
                resource_arn = resource.get('ResourceARN', '')
                if resource_arn:
                    # Extract region from ARN format: arn:aws:service:region:account-id:resource
                    arn_parts = resource_arn.split(':')
                    if len(arn_parts) >= 4 and arn_parts[3]:
                        region = arn_parts[3]
                        active_regions.add(region)
        
        return sorted(list(active_regions))
        
    except Exception as e:
        print(f"⚠️ Warning: Could not fetch active regions for account {account_id}: {e}")
        return []

def get_active_regions_multi_region(session, account_id):
    """
    Get active regions for an account by querying tagged resources across multiple regions.
    
    Args:
        session: boto3 session for the account
        account_id (str): AWS account ID
        
    Returns:
        list: Sorted list of active regions
    """
    # List of regions to scan - add more as needed
    regions_to_scan = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
        'ca-central-1', 'sa-east-1'
    ]
    
    active_regions = set()
    resource_count_by_region = {}
    resource_count_by_service = {}
    ec2_resource_types = {}
    total_resources = 0
    page_count = 0
    sample_resources = []
    region_samples = {}  # Group samples by region
    
    try:
        print(f"  🔍 Starting region detection for account {account_id} across {len(regions_to_scan)} regions...")
        
        # Scan each region separately since the API is regional
        for scan_region in regions_to_scan:
            try:
                print(f"    🌍 Checking region: {scan_region}")
                tagging_client = session.client('resourcegroupstaggingapi', region_name=scan_region)
                paginator = tagging_client.get_paginator('get_resources')
                region_resources = 0
                
                for page in paginator.paginate(ResourcesPerPage=50):
                    page_count += 1
                    resources = page.get('ResourceTagMappingList', [])
                    page_resource_count = len(resources)
                    region_resources += page_resource_count
                    total_resources += page_resource_count
                    
                    for resource in resources:
                        resource_arn = resource.get('ResourceARN', '')
                        if resource_arn:
                            # Extract region from ARN format: arn:aws:service:region:account-id:resource
                            arn_parts = resource_arn.split(':')
                            
                            if len(arn_parts) >= 4:
                                service = arn_parts[2] if len(arn_parts) > 2 else 'unknown'
                                region = arn_parts[3] if arn_parts[3] else 'global'
                                
                                # Special handling for S3: S3 ARNs don't include region
                                # but we know the region from which API call we're making
                                if service == 's3' and (not region or region == 'global'):
                                    region = scan_region  # Use the region we're scanning from
                                    print(f"      🪣 S3 resource mapped to region {scan_region}: {resource_arn}")
                                
                                # Special handling for other services that might not have region in ARN
                                elif service in ['iam', 'cloudfront', 'route53'] and (not region or region == 'global'):
                                    region = 'global'  # These are truly global services
                                
                                # Extract EC2 resource type for detailed analysis
                                resource_type = 'unknown'
                                if service == 'ec2' and len(arn_parts) >= 6:
                                    # Format: arn:aws:ec2:region:account:resource-type/resource-id
                                    resource_type_part = arn_parts[5]
                                    if '/' in resource_type_part:
                                        resource_type = resource_type_part.split('/')[0]
                                    else:
                                        resource_type = resource_type_part
                                
                                # Count resources by region, service, and EC2 type
                                resource_count_by_region[region] = resource_count_by_region.get(region, 0) + 1
                                resource_count_by_service[service] = resource_count_by_service.get(service, 0) + 1
                                
                                if service == 'ec2':
                                    ec2_resource_types[resource_type] = ec2_resource_types.get(resource_type, 0) + 1
                                
                                # Only add non-empty regions to active regions (skip global services)
                                if region and region != 'global':
                                    active_regions.add(region)
                                
                                # Collect sample resources grouped by region (up to 10 per region)
                                if region not in region_samples:
                                    region_samples[region] = []
                                
                                if len(region_samples[region]) < 10:
                                    region_samples[region].append({
                                        'arn': resource_arn,
                                        'service': service,
                                        'region': region,
                                        'resource_type': resource_type if service == 'ec2' else service,
                                        'tags': len(resource.get('Tags', []))
                                    })
                                
                                # Also keep overall samples for backward compatibility
                                if len(sample_resources) < 50:
                                    sample_resources.append({
                                        'arn': resource_arn,
                                        'service': service,
                                        'region': region,
                                        'resource_type': resource_type if service == 'ec2' else service,
                                        'tags': len(resource.get('Tags', []))
                                    })
                            else:
                                print(f"      ⚠️  Invalid ARN format: {resource_arn}")
                
                if region_resources > 0:
                    print(f"      ✅ Found {region_resources} tagged resources in {scan_region}")
                else:
                    print(f"      ⚪ No tagged resources in {scan_region}")
                    
            except Exception as e:
                print(f"      ❌ Error scanning {scan_region}: {e}")
                continue
        
        # Print detailed debugging information
        print(f"  📊 Region Detection Summary for Account {account_id}:")
        print(f"    • Total pages processed: {page_count}")
        print(f"    • Total tagged resources found: {total_resources}")
        print(f"    • Active regions detected: {sorted(list(active_regions))}")
        print(f"    • Resources by region: {dict(sorted(resource_count_by_region.items()))}")
        print(f"    • Resources by service: {dict(sorted(resource_count_by_service.items()))}")
        
        # Print EC2 resource type breakdown with ALL ARNs
        if ec2_resource_types:
            print(f"  🏗️  EC2 Resource Types Breakdown:")
            for resource_type, count in sorted(ec2_resource_types.items()):
                print(f"    • {resource_type}: {count}")
        
        # Print ALL resources grouped by EC2 resource type (not just samples)
        # Wrap this in try-catch to prevent SCP errors from breaking the main function
        try:
            if ec2_resource_types:
                print(f"  📋 ALL EC2 Resources by Type and Region:")
                
                # Use a working client from us-east-1 for detailed processing
                working_client = session.client('resourcegroupstaggingapi', region_name='us-east-1')
                
                # Collect all EC2 resources by type
                ec2_resources_by_type = {}
                
                # Re-process all resources to collect EC2 resources by type
                paginator = working_client.get_paginator('get_resources')
                for page in paginator.paginate(ResourcesPerPage=50):
                    for resource in page.get('ResourceTagMappingList', []):
                        resource_arn = resource.get('ResourceARN', '')
                        if resource_arn and ':ec2:' in resource_arn:
                            arn_parts = resource_arn.split(':')
                            if len(arn_parts) >= 6:
                                region = arn_parts[3] if arn_parts[3] else 'global'
                                resource_type_part = arn_parts[5]
                                resource_type = resource_type_part.split('/')[0] if '/' in resource_type_part else resource_type_part
                                
                                if resource_type not in ec2_resources_by_type:
                                    ec2_resources_by_type[resource_type] = []
                                
                                ec2_resources_by_type[resource_type].append({
                                    'arn': resource_arn,
                                    'region': region,
                                    'tags': len(resource.get('Tags', []))
                                })
                
                # Print all resources for each type
                for resource_type in sorted(ec2_resources_by_type.keys()):
                    resources = ec2_resources_by_type[resource_type]
                    print(f"    🔧 {resource_type.upper()} ({len(resources)} total):")
                    
                    # Group by region for this resource type
                    by_region = {}
                    for res in resources:
                        region = res['region']
                        if region not in by_region:
                            by_region[region] = []
                        by_region[region].append(res)
                    
                    # Print resources grouped by region
                    for region in sorted(by_region.keys()):
                        region_resources = by_region[region]
                        print(f"      🌍 {region} ({len(region_resources)} resources):")
                        for i, res in enumerate(region_resources, 1):
                            print(f"        {i:2d}. {res['tags']} tags | {res['arn']}")
                    print()  # Empty line between resource types
        except Exception as ec2_error:
            print(f"  ⚠️ Warning: Could not process detailed EC2 resources: {ec2_error}")
            print(f"     This doesn't affect region detection - continuing...")
        
        # Print sample resources grouped by region (keep this for non-EC2 services)
        print(f"  📋 Sample Resources by Region (All Services):")
        for region in sorted(region_samples.keys()):
            samples = region_samples[region]
            print(f"    🌍 {region} ({len(samples)} samples shown):")
            for i, res in enumerate(samples, 1):
                resource_display = f"{res['resource_type']}" if res['service'] == 'ec2' else f"{res['service']}"
                print(f"      {i:2d}. {resource_display:20} | {res['tags']} tags | {res['arn']}")
        
        # Special focus on us-west-2 if it exists
        if 'us-west-2' in region_samples:
            print(f"  🎯 FOUND US-WEST-2 RESOURCES! ({len(region_samples['us-west-2'])} samples)")
            for i, res in enumerate(region_samples['us-west-2'], 1):
                print(f"    {i}. {res['resource_type']:20} | {res['arn']}")
        elif 'us-west-2' not in active_regions:
            print(f"  ❌ NO US-WEST-2 RESOURCES FOUND in tagged resources")
            print(f"     This means either:")
            print(f"     • No resources in us-west-2 have tags")
            print(f"     • VPCs and related resources in us-west-2 are untagged")
        
        # DEBUG: Check what we're about to return
        print(f"  🔍 DEBUG: About to return active_regions: {sorted(list(active_regions))}")
        print(f"  🔍 DEBUG: active_regions set contains: {active_regions}")
        print(f"  🔍 DEBUG: Length of active_regions: {len(active_regions)}")
        
        if not active_regions:
            print(f"  ⚠️  No active regions found - this could mean:")
            print(f"      • No tagged resources exist in this account")
            print(f"      • All resources are global services (no region in ARN)")
            print(f"      • Permission issues with Resource Groups Tagging API")
        else:
            print(f"  ✅ SUCCESS: Found {len(active_regions)} active regions: {sorted(list(active_regions))}")
        
        final_result = sorted(list(active_regions))
        print(f"  🔍 DEBUG: Final result being returned: {final_result}")
        return final_result
        
    except Exception as e:
        print(f"  ❌ Error fetching active regions for account {account_id}: {e}")
        print(f"     This could be due to:")
        print(f"     • Missing 'tag:GetResources' permission")
        print(f"     • Network connectivity issues")
        print(f"     • API rate limiting")
        print(f"  🔍 DEBUG: Exception occurred, returning empty list")
        return []

def map_regions_to_groups(active_regions):
    """
    Map active regions to region groups.
    
    Args:
        active_regions (list): List of active regions
        
    Returns:
        tuple: (region_group, regions_string)
    """
    if not active_regions:
        return '', ''
    
    # Find which region groups are represented
    active_groups = set()
    mapped_regions = []
    
    for region in active_regions:
        for group_name, group_regions in REGION_GROUPS.items():
            if region in group_regions:
                active_groups.add(group_name)
                mapped_regions.append(region)
                break
    
    # If no regions match our defined groups, return empty
    if not mapped_regions:
        return '', ''
    
    # Determine region group
    if len(active_groups) > 1:
        region_group = "multi"
    elif len(active_groups) == 1:
        region_group = list(active_groups)[0]
    else:
        region_group = ''
    
    # Create comma-separated regions string
    regions_string = ','.join(sorted(mapped_regions))
    
    return region_group, regions_string

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

def assume_member_account_role(org_session, member_account_id, member_role_name, session_name="MemberAccountSession"):
    """
    Assume a role in a member account using the organization account session.
    
    Args:
        org_session (boto3.Session): The organization account session
        member_account_id (str): Member account ID
        member_role_name (str): Name of the IAM role to assume in the member account
        session_name (str): Name for the role session
        
    Returns:
        boto3.Session: A boto3 session with the assumed member account role credentials
    """
    try:
        # Use the organization session to assume the member account role via regular STS
        sts_client = org_session.client('sts', region_name=REGION)
        role_arn = f"arn:aws:iam::{member_account_id}:role/{member_role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
        )
        
        creds = response['Credentials']
        
        # Create a boto3 session with the member account credentials
        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken'],
            region_name=REGION
        )
        
        return session
        
    except Exception as e:
        raise Exception(f"Error assuming member account role {member_role_name} in account {member_account_id}: {str(e)}")

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AWS Organization Account Metadata Collection Script with OIDC Authentication')
    parser.add_argument('--member-role', 
                        default='tenant-compass-member-role',
                        help='IAM role name to use for accessing member accounts to get region information (default: tenant-compass-member-role)')
    
    args = parser.parse_args()
    member_role_name = args.member_role
    
    print(f" Using member account role: {member_role_name}")
    
    # Validate required environment variables
    required_vars = ['OUTPUT_BUCKET', 'DYNAMO_TABLE_NAME', 'CROSS_ACCOUNT_OIDC_ROLE_NAME',
                     'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f" Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables in your .env file or environment.")
        sys.exit(1)

    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    table = dynamodb.Table(DYNAMO_TABLE_NAME)

    try:
        tenant_ids = []
        scan_kwargs = {
            'FilterExpression': Attr('tenant_type').eq('Cloud Usage') & Attr('tenant_status').eq('Active') & Attr('cloud_service_provider').eq('AWS') & Attr('mgmt_category').is_in(['Known Managed', 'Known Partially Managed'])
        }

        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])
        tenant_ids.extend(item['tenant_id'] for item in items)

        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], **scan_kwargs)
            items = response.get('Items', [])
            tenant_ids.extend(item['tenant_id'] for item in items)

        print(f" Total active Cloud Usage tenant accounts found: {len(tenant_ids)}")
        print("Tenant IDs:", tenant_ids)

    except Exception as e:
        print(f" Error scanning DynamoDB table: {e}")
        return

    s3 = boto3.client('s3', region_name=REGION)
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')

    for org_account_id in tenant_ids:
        try:
            print(f"\n Processing Org account: {org_account_id}")
            # Use OIDC authentication instead of direct role assumption
            session = assume_role_with_oidc(org_account_id, ROLE_NAME)
            org_client = session.client('organizations', region_name=REGION)
            identity_client = session.client('sts', region_name=REGION)
            region_client = session.client('account', region_name=REGION)
            tagging_client = session.client('resourcegroupstaggingapi', region_name=REGION)

            org_info = org_client.describe_organization()['Organization']
            if org_info['MasterAccountId'] != org_account_id:
                print(f" Skipping {org_account_id}: Not a management account.")
                continue

            member_accounts = []
            paginator = org_client.get_paginator('list_accounts')
            for page in paginator.paginate():
                print(f" Fetched {len(page['Accounts'])} accounts from paginator")
                member_accounts.extend(page['Accounts'])


            # for org account name in the filename
            try:
                mgmt_account = org_client.describe_account(AccountId=org_account_id)['Account']
                raw_org_name = mgmt_account['Name']
                org_account_name = re.sub(r'[^A-Za-z0-9-]+', '-', raw_org_name).strip('-')
            except Exception as e:
                print(f" Warning: Could not fetch name for Org account {org_account_id}: {e}")
                org_account_name = "unknown"

            print(f" Total member accounts in org {org_account_id}: {len(member_accounts)}")

            all_account_data = []
            for account in member_accounts:
                account_id = account['Id']
                account_name = account['Name']
                account_status = account['Status']

                env_value = ''
                aide_id_value = ''
                try:
                    tags_response = org_client.list_tags_for_resource(ResourceId=account_id)
                    # Keep original tag keys (don't convert to lowercase) for robust tag detection
                    tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                    
                    # Use helper function to find tag values by checking multiple variations
                    env_value = find_tag_value(tags, ENVIRONMENT_TAG_VARIATIONS)
                    aide_id_value = find_tag_value(tags, AIDE_ID_TAG_VARIATIONS)
                    
                except Exception as e:
                    print(f" Warning: Could not fetch tags for account {account_id}: {e}")

                # Get active regions and map to region groups
                region_group = ''
                regions = ''
                account_session = None  # Initialize to avoid scope issues
                
                try:
                    if account_id == org_account_id:
                        # For organization account, use the existing organization session
                        account_tagging_client = tagging_client
                        account_session = session  # Use main session for org account
                        print(f"🌍 Using organization session for account {account_id} (management account)")
                    else:
                        # For member accounts, assume the member role using the organization session
                        try:
                            account_session = assume_member_account_role(session, account_id, member_role_name)
                            account_tagging_client = account_session.client('resourcegroupstaggingapi', region_name=REGION)
                            print(f"🌍 Using member role {member_role_name} for account {account_id}")
                        except Exception as role_error:
                            print(f"❌ Failed to assume role {member_role_name} in account {account_id}: {role_error}")
                            # Set both to None to skip region detection
                            account_tagging_client = None
                            account_session = None
                    
                    if account_tagging_client and account_session:
                        # Use the session for multi-region scanning
                        active_regions = get_active_regions_multi_region(account_session, account_id)
                        region_group, regions = map_regions_to_groups(active_regions)
                        print(f"🌍 Account {account_id}: Active regions: {active_regions}, Group: {region_group}, Regions: {regions}")
                    else:
                        print(f"⚠️ Skipping region detection for account {account_id} due to role assumption failure")
                    
                except Exception as e:
                    if account_id == org_account_id:
                        print(f"⚠️ Warning: Could not determine active regions for organization account {account_id}: {e}")
                    else:
                        print(f"⚠️ Warning: Could not determine active regions for member account {account_id}: {e}")

                # Always add account data to CSV, even if region detection failed
                print(f"📝 Adding account {account_id} ({account_name}) to CSV with regions: {regions}")
                account_data = {
                    "Account_ID": account_id,
                    "Account_Name": account_name,
                    "Org_ID": org_info['Id'],
                    "Tenant_Name": org_info['MasterAccountId'],
                    "CSP": "AWS",
                    "Billing_Account_State": account_status,
                    "Region_Group": region_group,
                    "Regions": regions,
                    "Tenant_ID": org_info['MasterAccountId'],
                    "Environment": env_value,
                    "Aide_ID": aide_id_value
                }
                
                all_account_data.append(account_data)
                print(f"✅ Account {account_id} added successfully. Total accounts in list: {len(all_account_data)}")
                print(f"   Account data: {account_data}")

            print(f"\n📊 Final account processing summary for Org {org_account_id}:")
            print(f"   Total accounts processed: {len(member_accounts)}")
            print(f"   Total accounts in all_account_data: {len(all_account_data)}")
            
            if not all_account_data:
                print(f"❌ No member accounts found for Org {org_account_id}.")
                continue

            # Log each account before sorting
            print(f"📋 Accounts before sorting:")
            for i, acc in enumerate(all_account_data):
                print(f"   {i+1}. {acc['Account_ID']} ({acc['Account_Name']}) - Regions: {acc['Regions']}")

            all_account_data.sort(key=lambda x: x['Account_ID'] != org_account_id)
            
            # Log each account after sorting
            print(f"📋 Accounts after sorting:")
            for i, acc in enumerate(all_account_data):
                print(f"   {i+1}. {acc['Account_ID']} ({acc['Account_Name']}) - Regions: {acc['Regions']}")

            print(f"📄 Starting CSV generation with {len(all_account_data)} accounts...")
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=all_account_data[0].keys())
            writer.writeheader()
            
            for i, row in enumerate(all_account_data):
                print(f"   Writing row {i+1}: {row['Account_ID']} ({row['Account_Name']}) - Regions: {row['Regions']}")
                writer.writerow(row)
            
            print(f"✅ CSV generation completed. CSV size: {len(output.getvalue())} characters")

            csv_key = f"{org_account_id}_aws_{org_account_name}_tc.csv"
            s3.put_object(Bucket=S3_BUCKET, Key=csv_key, Body=output.getvalue())
            print(f" Uploaded metadata for Org {org_account_id} to S3: {csv_key}")

            # Save to local file system (optional)
            if SAVE_LOCAL:
                local_path = OUTPUT_DIR / csv_key
                with open(local_path, 'w') as f:
                    f.write(output.getvalue())
                print(f" Saved local backup at: {local_path}")

        except Exception as e:
            print(f" Skipping Org account {org_account_id} due to error: {e}")

if __name__ == '__main__':
    main()
