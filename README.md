

Pre-Reqs
* Cloudtrail must be enabled
* 



Note that in Terraform the aws_cloudwatch_event resource is used. This is identical to EventBridge as they share the same API





Filter examples
## Filters

# AWS Config Changes (config.amazonaws.com)
{
  "source": ["aws.config"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["config.amazonaws.com"],
    "eventName": [
      "StopConfigurationRecorder",
      "DeleteDeliveryChannel",
      "PutDeliveryChannel",
      "PutConfigurationRecorder"
    ]
  }
}


# Cloudtrail Changes
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "CreateTrail",
      "UpdateTrail",
      "DeleteTrail",
      "StartLogging",
      "StopLogging"
    ]
  }
}

# KMS Key Deletions (kms.amazonaws.com)
{
  "source": ["aws.kms"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["kms.amazonaws.com"],
    "eventName": [
      "DisableKey",
      "ScheduleKeyDeletion"
    ]
  }
}


# Failed Console logins
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "responseElements": {
      "ConsoleLogin": ["Failure"]
    }
  }
}

# IAM Policy Changes
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "DeleteGroupPolicy",
      "DeleteRolePolicy",
      "DeleteUserPolicy",
      "PutGroupPolicy",
      "PutRolePolicy",
      "PutUserPolicy",
      "CreatePolicy",
      "DeleteRolePolicy",
      "CreatePolicyVersion",
      "DeletePolicyVersion",
      "AttachRolePolicy",
      "DetachRolePolicy",
      "AttachUserPolicy",
      "DetachUserPolicy",
      "AttachGroupPolicy",
      "DetachGroupPolicy"
    ]
  }
}


# NACL Changes
{
  "source": ["aws.vpc"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "CreateNetworkAcl",
      "CreateNetworkAclEntry",
      "DeleteNetworkAcl",
      "DeleteNetworkAclEntry",
      "ReplaceNetworkAclEntry",
      "ReplaceNetworkAclAssociation"
    ]
  }
}

# Network Gateway changes
{
  "source": ["aws.vpc"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": [
      "CreateCustomerGateway",
      "DeleteCustomerGateway",
      "AttachInternetGateway",
      "CreateInternetGateway",
      "DeleteInternetGateway",
      "DetachInternetGateway"
    ]
  }
}

# No MFA console logins
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "additionalEventData": {
      "MFAUsed": ["No"]
    }
  }
}



# RootAccountLogins
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"]
    },
    "userIdentity": {
      "invokedBy": [ { "exists": false } ]
    },
    "eventType": ["AwsServiceEvent", "AwsConsoleSignIn"]
  }
}


# RouteTable Changes
{
  "source": ["aws.vpc"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "CreateRoute",
      "CreateRouteTable",
      "ReplaceRoute",
      "ReplaceRouteTableAssociation",
      "DeleteRouteTable",
      "DeleteRoute",
      "DisassociateRouteTable"
    ]
  }
}

# S3 Bucket Policy Changes
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": [
      "PutBucketAcl",
      "PutBucketPolicy",
      "PutBucketCors",
      "PutBucketLifecycle",
      "PutBucketReplication",
      "DeleteBucketPolicy",
      "DeleteBucketCors",
      "DeleteBucketLifecycle",
      "DeleteBucketReplication"
    ]
  }
}

# Security Group Changes
{
  "source": ["aws.vpc"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "RevokeSecurityGroupEgress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}


# Unauthorized API calls
#{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "errorCode": ["AccessDenied", "UnauthorizedOperation"]
}

# VPC Change Filter
{
  "source": ["aws.vpc"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "CreateVpc",
      "DeleteVpc",
      "ModifyVpcAttribute",
      "AcceptVpcPeeringConnection",
      "CreateVpcPeeringConnection",
      "DeleteVpcPeeringConnection",
      "RejectVpcPeeringConnection",
      "AttachClassicLinkVpc",
      "DetachClassicLinkVpc",
      "DisableVpcClassicLink",
      "EnableVpcClassicLink"
    ]
  }
}