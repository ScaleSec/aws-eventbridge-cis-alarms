import boto3

def lambda_handler(event, context):
    eventSource = event['detail']['eventSource']
    eventName = event['detail']['eventName']

    if eventSource == "cloudtrail.amazonaws.com":
        print("Identified Cloudtrail CIS event")
        if eventName == "StopLogging":
            print("Remediating Cloudtrail StopLogging event by starting trail")
            client = boto3.client('cloudtrail')
            client.start_logging(Name= event['detail']['requestParameters']['name'])     