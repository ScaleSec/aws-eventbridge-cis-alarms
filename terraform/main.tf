locals {
  name   = "cis-alerts"
  events = fileset("${path.module}/templates/", "event-*")
}

data "aws_caller_identity" "current" {}

# SNS Topic for Notifications
resource "aws_sns_topic" "cis-alerts" {
  name = local.name
}

resource "aws_sns_topic_policy" "sns" {
  arn    = aws_sns_topic.cis-alerts.arn
  policy = data.aws_iam_policy_document.sns.json
}

data "aws_iam_policy_document" "sns" {
  statement {
    sid     = "AllowEventBridge"
    effect  = "Allow"
    actions = ["SNS:Publish"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [aws_sns_topic.cis-alerts.arn]
  }

  statement {
    sid    = "AllowUserSubscriptions"
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
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [aws_sns_topic.cis-alerts.arn]

    condition {
      test     = "StringLike"
      variable = "AWS:SourceOwner"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

# Lambda For Remediation
resource "aws_iam_role" "cis-remediation-lambda" {
  name = "${local.name}-remediation-lambda-role"

  assume_role_policy = file("${path.module}/templates/remediation-lambda-role-policy.tmpl.json")
}

resource "aws_iam_policy" "cloudtrail" {
  name        = "cis_remediation_lambda-policy"
  path        = "/"
  description = "IAM policy for lambda that executes CIS remediation actions"
  policy      = file("${path.module}/templates/cloudtrail-logging-policy.tmpl.json")
}

resource "aws_iam_role_policy_attachment" "cloudtrail-policy" {
  role       = aws_iam_role.cis-remediation-lambda.name
  policy_arn = aws_iam_policy.cloudtrail.arn
}

resource "aws_iam_role_policy_attachment" "lambda-exec-policy" {
  role       = aws_iam_role.cis-remediation-lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaExecute"
}

data "archive_file" "lambda-archive" {
  type        = "zip"
  source_file = "../lambda-src/remediate.py"
  output_path = "${path.module}/lambda.zip"
}

resource "aws_lambda_function" "remediation" {
  filename         = "${path.module}/lambda.zip"
  source_code_hash = data.archive_file.lambda-archive.output_base64sha256
  function_name    = "${local.name}-remediation-lambda"
  role             = aws_iam_role.cis-remediation-lambda.arn
  handler          = "remediate.lambda_handler"
  runtime          = "python3.8"
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
}

# Eventbridge rules and target configuration
resource "aws_cloudwatch_event_rule" "rules" {
  for_each = local.events

  name          = "${local.name}-${regex("^(?:event-)(.*?)(?:\\.tmpl\\.json)", each.value)[0]}"
  description   = "Respond to ${replace(regex("^(?:event-)(.*?)(?:\\.tmpl\\.json)", each.value)[0], "-", " ")}"
  event_pattern = file("${path.module}/templates/${each.value}")
}

resource "aws_cloudwatch_event_target" "sns" {
  for_each = aws_cloudwatch_event_rule.rules

  rule      = each.value.name
  target_id = "SendToSNS"
  arn       = aws_sns_topic.cis-alerts.arn

  depends_on = [
    aws_sns_topic.cis-alerts,
    aws_cloudwatch_event_rule.rules
  ]
}

resource "aws_cloudwatch_event_target" "lambda" {
  for_each = aws_cloudwatch_event_rule.rules

  rule      = each.value.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.remediation.arn
}

