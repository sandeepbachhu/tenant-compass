# AWS Organization Account Metadata Collection Flow Diagram

This document provides a detailed visual representation of how the `ec2_tc_script_save_local.py` script interacts with various AWS services to collect and process organization account metadata.

## High-Level Architecture

```mermaid
graph TD
    subgraph "EC2 Instance / Local Environment"
        A[Python Script] --> B[Load Environment Variables]
        B --> C[Initialize AWS Clients]
    end
    
    subgraph "AWS Services"
        D[(DynamoDB Table)]
        E[AWS Organizations]
        F[AWS STS]
        G[S3 Bucket]
    end
    
    C --> D
    D --> H[List of Tenant IDs]
    H --> I[Process Each Tenant]
    I --> F
    F --> J[Assume Cross-Account Role]
    J --> E
    E --> K[Retrieve Org & Account Data]
    K --> L[Generate CSV Report]
    L --> G
    L --> M[Local Storage]
```

## Detailed Process Flow

```mermaid
sequenceDiagram
    participant Script as Python Script
    participant DDB as DynamoDB
    participant STS as AWS STS
    participant Org as AWS Organizations
    participant S3 as S3 Bucket
    
    Note over Script: Script starts execution
    Script->>Script: Load environment variables
    
    Script->>DDB: Scan table for active AWS Cloud Usage tenants
    DDB-->>Script: Return tenant IDs
    
    loop For each tenant ID (org account)
        Script->>STS: AssumeRole request for cross-account access
        STS-->>Script: Return temporary credentials
        
        Script->>Org: DescribeOrganization request
        Org-->>Script: Return organization details
        
        Script->>Org: ListAccounts request (paginated)
        Org-->>Script: Return member accounts
        
        loop For each member account
            Script->>Org: ListTagsForResource request
            Org-->>Script: Return account tags
            
            Note over Script: Process account metadata
        end
        
        Note over Script: Generate CSV report
        
        Script->>S3: Upload CSV to bucket
        S3-->>Script: Confirm upload
        
        Note over Script: Save local copy if SAVE_LOCAL=True
    end
    
    Note over Script: Script execution complete
```

## Cross-Account Access Pattern

```mermaid
graph TD
    subgraph "Account Running Script"
        A[EC2 Instance / Local Environment]
        B[IAM Role/User]
    end
    
    subgraph "Organization Account"
        C[Cross-Account IAM Role]
        D[Trust Policy]
        E[Organizations API]
    end
    
    A --> B
    B -->|"sts:AssumeRole"| C
    C --- D
    D -->|"Allows AssumeRole from Script Account"| B
    C -->|"Has permissions for"| E
    E -->|"Returns organization and account data"| A
```

## Data Flow and Processing

```mermaid
graph LR
    A[DynamoDB Scan] -->|"Tenant IDs"| B[Cross-Account Access]
    B -->|"Organization Data"| C[Account Metadata Collection]
    C -->|"Account Data"| D[CSV Generation]
    D -->|"CSV File"| E[S3 Upload]
    D -->|"CSV File"| F[Local Storage]
    
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style C fill:#bfb,stroke:#333,stroke-width:2px
    style D fill:#fbb,stroke:#333,stroke-width:2px
    style E fill:#fbf,stroke:#333,stroke-width:2px
    style F fill:#bff,stroke:#333,stroke-width:2px
```

## IAM Permission Flow

```mermaid
graph TD
    subgraph "Script Execution Role"
        A[IAM Role/User Running Script]
        B["dynamodb:Scan Permission"]
        C["sts:AssumeRole Permission"]
        D["s3:PutObject Permission"]
    end
    
    subgraph "Cross-Account Role in Each Org Account"
        E[IAM Role with Name from CROSS_ACCOUNT_ROLE_NAME]
        F["organizations:DescribeOrganization Permission"]
        G["organizations:ListAccounts Permission"]
        H["organizations:ListTagsForResource Permission"]
        I["Trust Policy Allowing Script Role"]
    end
    
    A --- B
    A --- C
    A --- D
    E --- F
    E --- G
    E --- H
    E --- I
    C -->|"Allows assuming"| E
    I -->|"Trusts"| A
