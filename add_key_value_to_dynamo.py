  import boto3
  import string
  
  
  # Generating password for the uploaded file from S3
  password = ''.join((secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8)))
	
	# Add file and password to DynamoDB table
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Dynamo_Table')
    response = table.put_item(
       Item={
            'File' : ''+ key +'',
            'Password' : ''+ value +'',
            
        }
    )
    return response
