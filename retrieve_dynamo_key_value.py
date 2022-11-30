import os
import boto3


def lambda_handler(event, context):
    dynamodb = boto3.client('dynamodb')
    response = dynamodb.get_item(
        TableName=os.environ['DynamoTable'],
        Key={
            'File': {
                'S': os.environ['Key']
            },
            'Password': {
                'S': os.environ['Value']
            }
        },
    )
    
    count = response['Item']
    return count
