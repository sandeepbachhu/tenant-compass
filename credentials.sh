#!/bin/bash
 
# Define variables
audience="api://{}/.default"
roleArn="arn:aws:iam::{}:role/{}"
sessionName="AWSAssumeRole"
clientSecret="{}"
clientId="{}"
#tokenUrl="https://sts.windows.net/{}/oauth2/v2.0/token"
tokenUrl="https://login.microsoftonline.com/{}/oauth2/v2.0/token"
 
# Step 1: Get access token
response=$(curl -s -X POST "$tokenUrl" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$clientId" \
  -d "scope=$audience" \
  -d "client_secret=$clientSecret" \
  -d "grant_type=client_credentials")
 
accessToken=$(echo "$response" | jq -r '.access_token')
 
if [ -z "$accessToken" ] || [ "$accessToken" == "null" ]; then
  echo "❌ Failed to retrieve access token." >&2
  echo "Response: $response" >&2
  exit 1
fi
 
# Step 2: Assume AWS role
assumeRoleResponse=$(aws sts assume-role-with-web-identity \
  --role-arn "$roleArn" \
  --role-session-name "$sessionName" \
  --web-identity-token "$accessToken" 2>&1)
 
if echo "$assumeRoleResponse" | jq -e '.Credentials' >/dev/null 2>&1; then
  :
else
  echo "❌ Failed to assume role." >&2
  echo "Response: $assumeRoleResponse" >&2
  exit 1
fi
 
# Step 3: Extract credentials
accessKeyId=$(echo "$assumeRoleResponse" | jq -r '.Credentials.AccessKeyId')
secretAccessKey=$(echo "$assumeRoleResponse" | jq -r '.Credentials.SecretAccessKey')
sessionToken=$(echo "$assumeRoleResponse" | jq -r '.Credentials.SessionToken')
expiration=$(echo "$assumeRoleResponse" | jq -r '.Credentials.Expiration')
 
# Step 4: Output credentials in JSON format to stdout
jq -n \
  --arg accessKeyId "$accessKeyId" \
  --arg secretAccessKey "$secretAccessKey" \
  --arg sessionToken "$sessionToken" \
  --arg expiration "$expiration" \
  '{
    Version: 1,
    AccessKeyId: $accessKeyId,
    SecretAccessKey: $secretAccessKey,
    SessionToken: $sessionToken,
    Expiration: $expiration
  }'