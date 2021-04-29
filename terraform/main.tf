data "aws_caller_identity" "current" {}

# SNS Topic for Notifications
resource "aws_sns_topic" "cis-notifications" {
  name = "CIS-Alerts"
}

resource "aws_sns_topic_policy" "default" {
  arn    = aws_sns_topic.cis-notifications.arn
  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid = "alloweventbridge"
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.cis-notifications.arn]
  }

  statement {
     sid = "allowusersubscriptions"
     effect = "Allow"
     actions = [
        "SNS:GetTopicAttributes",
        "SNS:SetTopicAttributes",
        "SNS:AddPermission",
        "SNS:RemovePermission",
        "SNS:DeleteTopic",
        "SNS:Subscribe",
        "SNS:ListSubscriptionsByTopic",
        "SNS:Publish",
        "SNS:Receive"
      ]

      principals {
         type = "AWS"
         identifiers = ["*"]
      }

      resources = [aws_sns_topic.cis-notifications.arn]

      condition {
          test = "StringLike"
          variable = "AWS:SourceOwner" 
          values = [data.aws_caller_identity.current.account_id] 
      }
  }
}

# Lambda For Remediation
resource "aws_iam_role" "cis_remediation_role" {
  name = "cis_remediation_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "cis_remediation_role_lambda_perms" {
  name        = "cis_remediation_lambda-policy"
  path        = "/"
  description = "IAM policy for lambda that executes CIS remediation actions"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "cloudtrail:StartLogging"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.cis_remediation_role.name
  policy_arn = aws_iam_policy.cis_remediation_role_lambda_perms.arn
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment_execute" {
  role       = aws_iam_role.cis_remediation_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaExecute"
}

data "archive_file" "lambda_archive" {
  type        = "zip"
  source_file = "${path.module}/src/remediate.py"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "remediation_lambda" {
  filename      = "${path.module}/lambda.zip"
  source_code_hash = data.archive_file.lambda_archive.output_base64sha256
  function_name = "EventBridge-CIS-Remediation"
  role          = aws_iam_role.cis_remediation_role.arn
  handler       = "remediate.lambda_handler"
  runtime       = "python3.8"
}

resource "aws_lambda_permission" "allow_eventbridge_invoke" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation_lambda.function_name
  principal     = "events.amazonaws.com"
}

# Eventbridge rules and target configuration
resource "aws_cloudwatch_event_rule" "CIS-Alert-4-1" {
  name        = "CIS-Alert-Unauthorized-API-Calls"
  description = "Respond to Unauthorized API Calls"

  event_pattern = <<EOF
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "errorCode": ["AccessDenied", "*UnauthorizedOperation"]
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-1" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-1.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-1" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-1.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-2" {
  name        = "CIS-Alert-Sign-In-Without-MFA"
  description = "Respond to Console login without MFA"

  event_pattern = <<EOF
    {
      "detail-type": ["AWS Console Sign In via CloudTrail"],
      "detail": {
        "eventName": ["ConsoleLogin"],
        "userIdentity": {
          "type": ["IAMUser"]
        },
        "additionalEventData": {
          "MFAUsed": [{ "anything-but": "Yes"}]
        },
        "responseElements": {
          "ConsoleLogin": ["Success"]
        }
      }
    }
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-2" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-2.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-2" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-2.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-3" {
  name        = "CIS-Alert-Root-Account-Usage"
  description = "Respond to Root Account Usage"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"],
      "invokedBy": [ { "exists": false } ]
    },
    "eventType": [{ "anything-but": "AwsServiceEvent"}]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-3" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-3.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-3" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-3.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-4" {
  name        = "CIS-Alert-IAM-Policy-Changes"
  description = "Respond to IAM Policy Changes"

  event_pattern = <<EOF
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
      "DeletePolicy",
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-4" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-4.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-4" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-4.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-5" {
  name        = "CIS-Alert-Cloudtrail-Changes"
  description = "Respond to Cloudtrail Changes"

  event_pattern = <<EOF
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-5" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-5.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-5" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-5.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-6" {
  name        = "CIS-Alert-Console-Login-Failures"
  description = "Respond to Console Login Failures"

  event_pattern = <<EOF
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "responseElements": {
      "ConsoleLogin": ["Failure"]
    }
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-6" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-6.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-6" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-6.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-7" {
  name        = "CIS-Alert-KMS-CMK-Deletions"
  description = "Respond to KMS CMK Deletion Actions"

  event_pattern = <<EOF
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-7" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-7.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-7" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-7.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-8" {
  name        = "CIS-Alert-S3-Bucket-Policy-Changes"
  description = "Respond to S3 Bucket Policy Changes"

  event_pattern = <<EOF
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-8" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-8.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-8" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-8.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-9" {
  name        = "CIS-Alert-AWSConfig-Changes"
  description = "Respond to AWS Config Service Changes"

  event_pattern = <<EOF
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-9" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-9.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-9" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-9.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-10" {
  name        = "CIS-Alert-Security-Group-Changes"
  description = "Respond to Security Group Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-10" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-10.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-10" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-10.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-11" {
  name        = "CIS-Alert-NACL-Changes"
  description = "Respond to NACL Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-11" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-11.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-11" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-11.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-12" {
  name        = "CIS-Alert-Network-Gateway-Changes"
  description = "Respond to Network Gateway Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-12" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-12.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-12" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-12.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-13" {
  name        = "CIS-Alert-Route-Table-Changes"
  description = "Respond to VPC Route Table Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-13" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-13.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-13" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-13.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-14" {
  name        = "CIS-Alert-VPC-Changes"
  description = "Respond to VPC Changes"

  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
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
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-14" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-14.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-14" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-14.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}

resource "aws_cloudwatch_event_rule" "CIS-Alert-4-15" {
  name        = "CIS-Alert-Organizations-Changes"
  description = "Respond to AWS Organizations Changes"

  event_pattern = <<EOF
{
  "source": ["aws.organizations"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["organizations.amazonaws.com"],
    "eventName": [
      "AcceptHandshake",
      "AttachPolicy",
      "CreateAccount",
      "CreateOrganizationalUnit",
      "CreatePolicy",
      "DeclineHandshake",
      "DeleteOrganization",
      "DeleteOrganizationalUnit",
      "DeletePolicy",
      "DetachPolicy",
      "DisablePolicyType",
      "EnablePolicyType",
      "InviteAccountToOrganization",
      "LeaveOrganization",
      "MoveAccount",
      "RemoveAccountFromOrganization",
      "UpdatePolicy",
      "UpdateOrganizationalUnit"
    ]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "sns-4-15" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-15.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-notifications.arn
}

resource "aws_cloudwatch_event_target" "lambda-4-15" {
  rule      = aws_cloudwatch_event_rule.CIS-Alert-4-15.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation_lambda.arn
}