#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import json
import sys
import asyncio
import boto3
import requests
import time
import urllib3
import os
from hashlib import sha1
from datetime import datetime
from colorama import Fore, Back, Style

from aiohttp import web
import concurrent.futures

from base64 import b64encode, b64decode
#from parameter import *
from requests_toolbelt.multipart.encoder import MultipartEncoder

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

async_clount=0
sid=""
FSA_VER="4.4"
headers = {"'Content-Type": "application/json"}
url = "https://10.9.0.10/jsonrpc"

username = os.getenv("fsa_username")
password = os.getenv("fsa_password")
AWS_key1 = os.getenv("aws_s3_key1")
AWS_sec1 = os.getenv("aws_s3_sec1")

def api_call(data):
    # call the FSA API
    rep_err = False
    try:
        rep = requests.post(url,headers=headers, data=json.dumps(data),verify=False )
    except Exception:
        rep_err = True
        pass
    if  rep_err:
        print("error during get, check ip")
        return ""
    if rep.status_code != 200:
        print(f'Something went wrong. status_code: {rep.status_code}')
        print (rep.text)
        return ""

    s=json.loads(rep.text)
    return s

def get_session_token():
    
    data = {"id": "1",
            "method": "exec", 
            "params": [{"passwd": password, "user": username, "url": "sys/login/user"}],
            "ver": FSA_VER }
    s = api_call( data )

    if s != "":
        return s["session"]
    else:
        print ("got no session ID")
        sys.exit(1)

def fsa_logout(sid):
    global async_clount
    data= {
            "method": "exec",
            "params": [
            {
            "url": "/sys/logout"
            }
            ],
            "session":sid,
            "id": 2,
            "ver": FSA_VER
        }           
    s = api_call( data )
    
    return(s)

class FSA:
    """FSA checker
    This class implements an uploader to check files
    with the FSA.
    """

    def __init__(self, host, sid,asc, verify=True, timeout=0.5):
        self.host = host
        self.sid = sid
        self.verify = verify
        self.timeout = timeout
        self.file_sha1 = ""
        self.asc=asc
        self.jsid=""

    def check_file_results(self): 
        # check if there is already a verdict
        data = {
            "method": "get",
            "params": [
            {
            "url": "/scan/result/file",
            "checksum":self.file_sha1,
            "ctype":"sha1"
            }
            ],
            "session":self.sid,
            "id": 13,
            "ver": FSA_VER
        }

        response = requests.post(
            url=self.host,
            json=data,
            verify=self.verify )

        return(json.loads(response.text))
    

    def check_jobs(self):
        # check for jobs of a submission, this info is also in "/scan/result/file"
        data={
                "method": "get",
                "params": [
                {
                "url": "/scan/result/get-jobs-of-submission",
                "sid": self.jsid,
                }
                ],
                "session": self.sid,
                "id":17,
            "ver": FSA_VER
            } 
        rjids = requests.post(
                url=url,
                json=data,
                verify=False )
        rjids=json.loads(rjids.text)
        jids=rjids["result"]["data"]["jids"]
        return(jids)
    
        
    def check_object(self, object, filename,size,asc):
        # upload a file and wait for verdict

        filePath = object
        fileFp = open(filePath, 'rb')
        self.file_sha1=sha1(fileFp.read()).hexdigest()
        fileFp.seek(0)
        #print("FFF:",filePath,fileFp.name,self.file_sha1)
                        
        """
        data={"method":"set",
                "params":[
                {
                "filename": b64encode(filename.encode('utf-8')).decode("utf-8"),
                "file": b64encode(object).decode("utf-8"),
                "comments": "this is test file #99",
                "enable_ai": 1,
                "forcedvm": 1,
                "overwrite_vm_list": "",
                "type": "file",
                "url": "/alert/ondemand/submit-file",
                "vrecord": 0
                }],
                "session": self.sid,
                "id":11,
                "ver": FSA_VER
        }
        
        file_len = len(data["params"][0]["file"])

        response = requests.post(
            url=self.host,
            json=data,
            verify=self.verify
        )
        """

        data={
            "comments": f"async {asc}",
            "enable_ai": 1,
            "forcedvm": 0,
            "overwrite_vm_list": "",
            "type": "file",
            "url": "/alert/ondemand/submit-file",
            "vrecord": 0,
            "session": self.sid,
            "id":11,
            "ver": FSA_VER
            }  



        # upload the file
        multipart_file_post_body = MultipartEncoder(fields={
                "data": (None, json.dumps(data), 'application/json'),
                "file": (fileFp.name, fileFp, 'application/octet-stream')
            })

        response = requests.post(self.host, data=multipart_file_post_body, headers={'Content-Type': multipart_file_post_body.content_type}, verify=False)


        r=json.loads(response.text)
        color=Fore.WHITE
        jsid = r["result"]["data"]["sid"]
        self.jsid=jsid
        print(f'{color}{self.asc} Submit to FSA: - {r["result"]["status"]["message"]} Size: {size:,} byte - SID: {jsid}') 
       
        ## check and wait for result

        sec=0
        wait = 20
        while True:
            color=Fore.BLUE
            r = self.check_file_results()# (self)
            #jids = self.check_jobs()
            #print(f'{color}{asc} Jobs FSA: {jids}') 
            code = r["result"]["status"]["code"]
            msg = r["result"]["status"]["message"]
            
            print(f'{color}{self.asc} Check Sec:{sec} - {code} {msg}')
            
            if code == 0: break
            sec += wait
            time.sleep(wait)
 
        return(r,jsid)


async def process_message(message):
    # this is called for 
    global async_clount
    
    await asyncio.sleep(0.1)
    async_clount += 1
    asc = async_clount
    ts_start=time.time()
    color=Fore.WHITE
    print(f'{color}{asc} Processing post: - {message["key"]}') 
    
    client = FSA(url, sid,asc, False)

    s3 = boto3.client('s3', aws_access_key_id=AWS_key1, aws_secret_access_key=AWS_sec1)

    # version for hash
    #response = s3.get_object(Bucket=message["bucket"], Key=message["key"])
    #object_content = response['Body'].read()
    #r= client.check_object(object_content, message["key"])
    
    #version for write to file
    file_name = "file_cache/" + message["key"].split('/')[-1]  # Extract file name from object key
    with open(file_name, 'wb') as f:
        s3.download_fileobj(message["bucket"], message["key"], f)
        f.seek(0)
   
    #version for in mem 
    #file_name =  message["key"].split('/')[-1]  # Extract file name from object key



    r,jsid = client.check_object(file_name, message["key"],message["size"],asc)
    
    
    ratings=r["result"]["data"]["rating"]
    color=Fore.GREEN
    for rating in ratings:
        if rating != 'Clean':
            color=Fore.RED
            print(f'{color}{asc} Jobs FSA: {r["result"]["data"]["jid"]}') 
            for jid in r["result"]["data"]["jid"]:
                data={
                    "id": 15,
                    "method": "get",
                    "params": [
                        {
                        "jid": jid,
                        "url": "/scan/result/job"
                        }
                    ],
                    "session": sid,
                    "ver": FSA_VER
                    }
                j_respond = requests.post(
                    url=url,
                    json=data,
                    verify=False )
                #print(f'{color}{asc} Job result: {j_respond.text}') 
                j_res=json.loads(j_respond.text)
                print(f'{color}{asc} Job result: {j_res["result"]["data"]["detail_url"]}')     
    

    print(f'{color}{asc} Processing FSA: - {r["result"]["status"]["message"]} -  {r["result"]["data"]["rating"]}') 

    #r= fsa_logout(sid)
    color=Fore.WHITE
    ts_total = int(time.time() - ts_start)
    print(f'{color}{asc} !!!!!!!!!!! Ready  in {ts_total} sec for {message["key"]}')
    

class HTTPServer:
    def __init__(self):
        self.app = web.Application()
        self.app.router.add_post('/fsa', self.schedule_tasks)

    async def schedule_tasks(self, request):
        message = await request.json()
        color=Fore.YELLOW
        print(f'{color}Incomeing POST: {message["key"]}')
    
        # Execute the async task in a separate thread with the POST data
        with concurrent.futures.ThreadPoolExecutor() as executor:
            loop = asyncio.get_event_loop()
            #result = await loop.run_in_executor(executor, lambda: self.run_async_task(message))
            result = await loop.run_in_executor(executor, self.run_async_task,message)

        return web.Response(text=f"Scheduled asynchronous task with POST data:")

    
    def start_server(self):
        web.run_app(self.app, host='0.0.0.0', port=8282)

    def run_async_task(self, message):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(process_message(message))
        return result

if __name__ == '__main__':
    now = datetime.now()
    dt_string = now.strftime("%Y-%m-%d %H:%M:%S")
    ts = time.time()
    print(dt_string,ts)
    sid = get_session_token()
    print(time.time()-ts)
    server = HTTPServer()
    server.start_server()

