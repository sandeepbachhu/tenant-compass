import boto3
import json
import csv
import io
import datetime
import os
from typing import Dict, List, Tuple, Set

# Environment variables
S3_BUCKET = os.environ.get('S3_BUCKET')
CROSS_ACCOUNT_ROLE_NAME = os.environ.get('CROSS_ACCOUNT_ROLE_NAME', 'OrganizationAccountAccessRole')

# Region group mapping
REGION_GROUPS = {
    "US": {"us-east-1", "us-east-2", "us-west-1", "us-west-2"},
    "UK": {"eu-west-2"},
    "EU": {"eu-north-1", "eu-west-1"},
    "BR": {"sa-east-1"}
}

def lambda_handler(event, context):
    """
    AWS Lambda function to test Resource Groups Tagging API across organization accounts.
    
    This function:
    1. Discovers the current AWS organization and all member accounts
    2. Assumes cross-account roles to access each member account
    3. Uses Resource Groups Tagging API to discover tagged resources
    4. Generates a CSV report with account metadata and region information
    5. Uploads the report to S3
    """
    
    print("🚀 Starting Lambda Tags API Test")
    
    # Validate environment variables
    if not S3_BUCKET:
        return {
            'statusCode': 400,
            'body': json.dumps('ERROR: S3_BUCKET environment variable is required')
        }
    
    print(f"📦 Using S3 bucket: {S3_BUCKET}")
    print(f"🔑 Using cross-account role: {CROSS_ACCOUNT_ROLE_NAME}")
    
    try:
        # Initialize AWS clients
        org_client = boto3.client('organizations')
        s3_client = boto3.client('s3')
        
        # Get organization information
        print("🏢 Getting organization information...")
        org_info = org_client.describe_organization()['Organization']
        org_id = org_info['Id']
        management_account_id = org_info['MasterAccountId']
        
        print(f"   Organization ID: {org_id}")
        print(f"   Management Account: {management_account_id}")
        
        # Get all accounts in the organization
        print("👥 Discovering organization accounts...")
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
        
        print(f"   Found {len(accounts)} accounts in organization")
        
        # Process each account
        all_account_data = []
        
        for account in accounts:
            account_id = account['Id']
            account_name = account['Name']
            account_status = account['Status']
            
            print(f"\n🔍 Processing account: {account_id} ({account_name})")
            
            # Get account tags (if any)
            env_value = ''
            try:
                tags_response = org_client.list_tags_for_resource(ResourceId=account_id)
                tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                env_value = tags.get('Environment', tags.get('environment', ''))
            except Exception as e:
                print(f"   ⚠️  Could not fetch account tags: {e}")
            
            # Get active regions using Resource Groups Tagging API
            region_group = ''
            regions = ''
            resource_summary = {}
            
            try:
                if account_id == management_account_id:
                    # For management account, use current session
                    print("   🏠 Using management account session")
                    session = boto3.Session()
                    active_regions, resource_summary = get_active_regions(session, account_id)
                else:
                    # For member accounts, assume cross-account role
                    print(f"   🔄 Assuming role {CROSS_ACCOUNT_ROLE_NAME} in member account")
                    session = assume_cross_account_role(account_id, CROSS_ACCOUNT_ROLE_NAME)
                    if session:
                        active_regions, resource_summary = get_active_regions(session, account_id)
                    else:
                        print(f"   ❌ Failed to assume role in account {account_id}")
                        active_regions = []
                        resource_summary = {}
                
                region_group, regions = map_regions_to_groups(active_regions)
                
                print(f"   🌍 Active regions: {active_regions}")
                print(f"   📊 Resource summary: {resource_summary}")
                print(f"   🏷️  Region group: {region_group}, Regions: {regions}")
                
            except Exception as e:
                print(f"   ❌ Error getting regions for account {account_id}: {e}")
            
            # Add account data to results
            all_account_data.append({
                "Account_ID": account_id,
                "Account_Name": account_name,
                "Org_ID": org_id,
                "Tenant_Name": management_account_id,
                "CSP": "AWS",
                "Billing_Account_State": account_status,
                "Region_Group": region_group,
                "Regions": regions,
                "Tenant_ID": management_account_id,
                "Environment": env_value,
                "Resource_Summary": json.dumps(resource_summary)
            })
        
        # Generate CSV report
        print(f"\n📄 Generating CSV report with {len(all_account_data)} accounts...")
        csv_content = generate_csv_report(all_account_data)
        
        # Upload to S3
        timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%SZ')
        csv_key = f"lambda-tags-test-{org_id}-{timestamp}.csv"
        
        print(f"📤 Uploading report to S3: {csv_key}")
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=csv_key,
            Body=csv_content,
            ContentType='text/csv'
        )
        
        print("✅ Lambda execution completed successfully!")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Tags API test completed successfully',
                'organization_id': org_id,
                'accounts_processed': len(all_account_data),
                's3_bucket': S3_BUCKET,
                's3_key': csv_key,
                'timestamp': timestamp
            })
        }
        
    except Exception as e:
        print(f"❌ Lambda execution failed: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def assume_cross_account_role(account_id: str, role_name: str) -> boto3.Session:
    """
    Assume a cross-account role in the specified account.
    
    Args:
        account_id: Target AWS account ID
        role_name: Name of the role to assume
        
    Returns:
        boto3.Session object or None if failed
    """
    try:
        sts_client = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"LambdaTagsTest-{account_id}"
        )
        
        credentials = response['Credentials']
        
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        return session
        
    except Exception as e:
        print(f"   ❌ Failed to assume role {role_arn}: {e}")
        return None

def get_active_regions(session, account_id: str) -> Tuple[List[str], Dict]:
    """
    Get active regions and resource summary for an account using Resource Groups Tagging API.
    Scans multiple regions since the API is regional, not global.
    
    Args:
        session: boto3 session for the account
        account_id: AWS account ID
        
    Returns:
        Tuple of (active_regions_list, resource_summary_dict)
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
    
    print(f"   🔍 Scanning tagged resources in account {account_id} across {len(regions_to_scan)} regions...")
    
    # Scan each region separately since the API is regional
    for region in regions_to_scan:
        try:
            print(f"     🌍 Checking region: {region}")
            tagging_client = session.client('resourcegroupstaggingapi', region_name=region)
            paginator = tagging_client.get_paginator('get_resources')
            region_resources = 0
            
            for page in paginator.paginate(ResourcesPerPage=50):
                resources = page.get('ResourceTagMappingList', [])
                region_resources += len(resources)
                total_resources += len(resources)
                
                for resource in resources:
                    resource_arn = resource.get('ResourceARN', '')
                    if resource_arn:
                        # Extract region and service from ARN
                        arn_parts = resource_arn.split(':')
                        
                        if len(arn_parts) >= 4:
                            service = arn_parts[2] if len(arn_parts) > 2 else 'unknown'
                            arn_region = arn_parts[3] if arn_parts[3] else 'global'
                            
                            # Special handling for S3: S3 ARNs don't include region
                            # but we know the region from which API call we're making
                            if service == 's3' and (not arn_region or arn_region == 'global'):
                                arn_region = region  # Use the region we're scanning from
                                print(f"         🪣 S3 resource mapped to region {region}: {resource_arn}")
                            
                            # Special handling for other services that might not have region in ARN
                            elif service in ['iam', 'cloudfront', 'route53'] and (not arn_region or arn_region == 'global'):
                                arn_region = 'global'  # These are truly global services
                            
                            # Count resources by region and service
                            resource_count_by_region[arn_region] = resource_count_by_region.get(arn_region, 0) + 1
                            resource_count_by_service[service] = resource_count_by_service.get(service, 0) + 1
                            
                            # Extract EC2 resource types for detailed analysis
                            if service == 'ec2' and len(arn_parts) >= 6:
                                resource_type_part = arn_parts[5]
                                resource_type = resource_type_part.split('/')[0] if '/' in resource_type_part else resource_type_part
                                ec2_resource_types[resource_type] = ec2_resource_types.get(resource_type, 0) + 1
                            
                            # Add to active regions (skip truly global services)
                            if arn_region and arn_region != 'global':
                                active_regions.add(arn_region)
            
            if region_resources > 0:
                print(f"       ✅ Found {region_resources} tagged resources in {region}")
            else:
                print(f"       ⚪ No tagged resources in {region}")
                
        except Exception as e:
            print(f"       ❌ Error scanning {region}: {e}")
            continue
    
    print(f"   📊 Total tagged resources found: {total_resources}")
    print(f"   🌍 Regions with resources: {dict(sorted(resource_count_by_region.items()))}")
    print(f"   🔧 Services: {dict(sorted(resource_count_by_service.items()))}")
    
    if ec2_resource_types:
        print(f"   🏗️  EC2 Types: {dict(sorted(ec2_resource_types.items()))}")
    
    # Create resource summary
    resource_summary = {
        'total_resources': total_resources,
        'regions': dict(sorted(resource_count_by_region.items())),
        'services': dict(sorted(resource_count_by_service.items())),
        'ec2_types': dict(sorted(ec2_resource_types.items())) if ec2_resource_types else {}
    }
    
    return sorted(list(active_regions)), resource_summary

def map_regions_to_groups(active_regions: List[str]) -> Tuple[str, str]:
    """
    Map active regions to region groups.
    
    Args:
        active_regions: List of active AWS regions
        
    Returns:
        Tuple of (region_group, regions_string)
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

def generate_csv_report(account_data: List[Dict]) -> str:
    """
    Generate CSV report from account data.
    
    Args:
        account_data: List of account dictionaries
        
    Returns:
        CSV content as string
    """
    if not account_data:
        return ""
    
    output = io.StringIO()
    fieldnames = account_data[0].keys()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    
    writer.writeheader()
    for row in account_data:
        writer.writerow(row)
    
    return output.getvalue()
