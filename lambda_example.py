import json
import urllib3
import boto3
from urllib.parse import unquote_plus

URL = "url to fsa_inthecloud"

def lambda_handler(event, context):
    
    message={}
    message["bucket"]=event["Records"][0]["s3"]["bucket"]["name"]
    message["key"]=event["Records"][0]["s3"]["object"]["key"] 
    message["region"]=event["Records"][0]["awsRegion"]
    message["size"]=event["Records"][0]["s3"]["object"]["size"]
    #message["event"]=event
    #message["context"]=str(context)
    S3URL = f'https://s3.console.aws.amazon.com/s3/object/{message["bucket"]}?region={message["region"]}&prefix={message["key"]}'
    message["s3url"]=S3URL
    message["key"]=unquote_plus(event["Records"][0]["s3"]["object"]["key"])
    
    #print(message)
    
    #S3URL = f'https://s3.console.aws.amazon.com/s3/object/{message["bucket"]}?region={message["region"]}&prefix={message["prefix"]}'
    #print(S3URL)
    
    if message["size"] >0:  # =0 means new folder
        http = urllib3.PoolManager()
        ret = http.request("POST",f"{URL}/fsa",body=json.dumps(message).encode('UTF-8'))

        return(ret.status)
        
    return() 
    