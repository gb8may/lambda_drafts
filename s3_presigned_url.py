import boto3
import urllib


def lambda_handler(event, context):
    # Get bucket and file information
    s3_client = boto3.client('s3')
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    
    message = 'This file got uploaded ' + key + ' to this bucket: ' + bucket_name
    print(message)
    
    # Generating signed URL
    url = boto3.client('s3').generate_presigned_url(
    ClientMethod='get_object', 
    Params={'Bucket': bucket_name, 'Key': key},
    ExpiresIn=300)
    
    message = url
    print(message)
