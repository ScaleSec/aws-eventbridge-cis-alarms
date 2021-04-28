# Cloudformation

## Pre-Requisites
* Cloudtrail should have at least one trail configured and enabled to properly demo the lambda
* Credentials - You must have AWS credentials exported to your environment variables or have a local profile you can use to run the commands below. 
* Permissions - The AWS credentials you use to deploy must have the ability to create Eventbridge rules and targets, Lambda functions, IAM roles and policies, and SNS topics
* An existing S3 bucket that lambda code can be uploaded to

## Usage Instructions
1. Setup your local credentials and verify you are deploying into the appropriate account. You can confirm by running `aws sts get-caller-identity`
3. Navigate in to the cloudformation directory
2. We must first create the lambda package and upload the package to S3. Run `aws cloudformation package --template-file cis-eventbridge.yaml --s3-bucket desired_s3_bucket --output-template-file packaged-template.json` replacing desired_s3_bucket with the bucket to upload the lambda package too. This will also create an updated cloudformation template called packaged-template.json. This is the template we will use to deploy.
3. Deploy the code by running `aws cloudformation deploy --template-file packaged-template.json --stack-name eventbridge-alerts --capabilities CAPABILITY_NAMED_IAM`


## Validate Functionality
* To validate the events are working you should subscribe your email to the CIS-Alerts topic created. This will allow you to receive an email whenever events are triggered. Once verified you can unsubscribe.
* You can verify the rules were created by viewing the EventBridge console. There should be 14 rules all starting with CIS-Alert
* Once deployed you can stop logging for an existing CloudTrail trail. The event should be triggered and the remediation lambda will re-enable the trail.
