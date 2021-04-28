# Terraform

## Pre-Requisites
* Terraform 0.14.0 or greater installed and configured
* Cloudtrail should have at least one trail configured and enabled to properly demo the lambda
* Credentials - You must have AWS credentials exported to your environment variables to run the code as is. If you wish to use a profile or run as a service then you will need to add the appropriate Terraform provider code to support that usage type
* Permissions - The AWS credentials you use to deploy must have the ability to create Eventbridge rules and targets, Lambda functions, IAM roles and policies, and SNS topics

## Usage Instructions
1. Setup your local credentials and verify you are deploying into the appropriate account. You can confirm by running `aws sts get-caller-identity`
2. Run `terraform plan` to see all resources that will be deployed
3. Run `terraform apply` to deploy. You will be prompted for the region to deploy the rules into (they are region specific)

To destroy the environment run `terraform destroy`

Note that in Terraform the aws_cloudwatch_event resource is used. This is identical to EventBridge as they share the same API


## Validate Functionality
* To validate the events are working you should subscribe your email to the CIS-Alerts topic created. This will allow you to receive an email whenever events are triggered. Once verified you can unsubscribe.
* Once deployed you can stop logging for an existing CloudTrail trail. The event should be triggered and the remediation lambda will re-enable the trail.