# Sample use-case for combining Cloud Defender and Cloud Insight API to check AL Agent deployment coverage
# Use lambda function to run the check and SNS to send the notification
# Author: welly.siauw@alertlogic.com
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
#
from __future__ import print_function
import sys, os, json, requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import boto3
from base64 import b64decode

#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#API headers
CD_HEADERS = {'content-type': 'application/json'}
CI_HEADERS = {'Accept': 'application/json'}

def lambda_handler(event, context):
    PARENT_CID = os.environ["PARENT_CID"]
    DC = os.environ["DC"]
    if DC == "DENVER":
        ALERT_LOGIC_CI_DC = ".alertlogic.com"
        ALERT_LOGIC_CD_DC = ".alertlogic.net"

    elif DC == "ASHBURN":
        ALERT_LOGIC_CI_DC = ".alertlogic.com"
        ALERT_LOGIC_CD_DC = ".alertlogic.com"

    elif DC == "NEWPORT":
        ALERT_LOGIC_CI_DC = ".alertlogic.co.uk"
        ALERT_LOGIC_CD_DC = ".alertlogic.co.uk"

    USER = os.environ["USER"]
    PASSWORD = boto3.client('kms').decrypt(CiphertextBlob=b64decode(os.environ["PASSWORD"]))['Plaintext']
    global API_KEY
    API_KEY = boto3.client('kms').decrypt(CiphertextBlob=b64decode(os.environ["API_KEY"]))['Plaintext']

    #Authenticate to Cloud Insight to get token
    TOKEN = str(authenticate(USER, PASSWORD, "api.cloudinsight" + ALERT_LOGIC_CI_DC))

    #Find CID
    print ("### Searching for AWS account under parent CID :" + PARENT_CID)
    MASTER_DIC=find_all_child(PARENT_CID, TOKEN, ALERT_LOGIC_CD_DC, ALERT_LOGIC_CI_DC)

    #Search and record AL Agent install per CID
    print ("### Tracking AL Agent install per CID")
    sns_message = search_and_record(MASTER_DIC, TOKEN, API_KEY, ALERT_LOGIC_CD_DC, ALERT_LOGIC_CI_DC)

    sns_client = boto3.client('sns')
    sns_response = sns_client.publish(
        TargetArn=os.environ["SNS_ARN"],
        Message=sns_message,
        Subject='AL Agent Report')
    print ("### SNS Response : " + str(json.dumps(sns_response, indent=4)))

    print (sns_message)

#Get all child under parent
def find_all_child(parent_cid, token, defender_dc, insight_dc):
    CID_DIC = get_CID(parent_cid, defender_dc)
    TEMP_MASTER_DIC = []
    if "child_chain" in CID_DIC:
        for CID_CHILD in CID_DIC["child_chain"]:
            print ("CID : " + str(CID_CHILD["customer_id"]))
            print ("Account Name : " + str(CID_CHILD["customer_name"]))
            TEMP_ENV_DIC = get_cloud_defender_env_by_cid(str(CID_CHILD["customer_id"]), token, insight_dc)
            for CD_ENV in TEMP_ENV_DIC:
                print ("  Cloud Defender Environment : " + str(CD_ENV["name"]))
                print ("  AWS Account : " + str(CD_ENV["type_id"]))
                ENV_ITEM = {}
                ENV_ITEM["CID"] = str( CID_CHILD["customer_id"] )
                ENV_ITEM["ACCOUNT_NAME"] = str( CID_CHILD["customer_name"] )
                ENV_ITEM["CD_NAME"] = str( CD_ENV["name"] )
                ENV_ITEM["AWS_ACC"] = str( CD_ENV["type_id"] )
                ENV_ITEM["ENV_ID"] = str( CD_ENV["id"] )
                TEMP_MASTER_DIC.append(ENV_ITEM)
            print ("\n")
    else:
        print ("No CID found")
    return TEMP_MASTER_DIC

#Get customer CID data
def get_CID(target_cid, defender_dc):
    try:
        API_ENDPOINT = "https://api" + defender_dc  + "/api/customer/v1/" + target_cid
        REQUEST = requests.get(API_ENDPOINT, headers=CI_HEADERS, auth=(API_KEY,''))
        RESULT = json.loads(REQUEST.text)
        return RESULT
    except Exception, e:
        #print ("Status code " + str(REQUEST.status_code))
        print(str(e))
        sys.exit()

#Get Deployment data from Cloud Insight
def get_cloud_defender_env_by_cid(target_cid, token, insight_dc):
    API_ENDPOINT = "https://api.cloudinsight" + insight_dc + "/environments/v1/" + target_cid + "?type=aws&defender_support=true"
    REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
    RESULT = json.loads(REQUEST.text)
    return RESULT["environments"]

#Loop through all AWS accounts to check deployment status
def search_and_record(target_dic, token, api_key, defender_dc, insight_dc):
    output = ""
    for item in target_dic:
        print("Account Name : " + str(item["ACCOUNT_NAME"]) + "\nCID : " + str(item["CID"]) )
        output = output + "Account Name : " + str(item["ACCOUNT_NAME"]) + "\n"
        output = output + "CID : " + str(item["CID"]) + " \n\n"

        if str(item["ENV_ID"]) != "n/a":
            CD_TARGET_CID=str(item["CID"])
            #Get list of EC2 assets running in the AWS account, filter for Cloud Insight appliance
            #TODO filter for Threat Manager appliance
            item["EC2_HOST"] = get_ci_host(insight_dc, token, CD_TARGET_CID, str(item["ENV_ID"]), "/assets?asset_types=h:host&h.name=!AlertLogic%20Security%20Appliance")
            #Get list of AL Agent / PHOST from the account
            item["PHOST"] = get_cd_phost(defender_dc, str(item["CID"]), str(item["AWS_ACC"]), "protectedhosts?type=host")

            print ("Env ID : " + str(item["ENV_ID"]))
            output = output + "Env ID : " + str(item["ENV_ID"]) + "\n"

            print ("AWS : " + str(item["AWS_ACC"]))
            output = output + "AWS : " + str(item["AWS_ACC"]) + "\n"

            print ("Host Count: " + str(item["EC2_HOST"]["rows"]))
            output = output + "Host Count: " + str(item["EC2_HOST"]["rows"]) + "\n"

            print ("PHOST Count: " + str(len(item["PHOST"])))
            output = output + "PHOST Count: " + str(len(item["PHOST"])) + "\n"

            print ("AL Agent missing / not installed on the following hosts:")
            output = output + "AL Agent missing / not installed on the following hosts:" + "\n"

            output = output + "\n" + who_is_missing(item["PHOST"], item["EC2_HOST"]["assets"]) + "\n"
            print ("\n")

        else:
            print("No CI Environment ID found - skipping\n")
            output = output + "No CI Environment ID found - skipping\n" + "\n"
    return output

#Loop through all EC2 instance and check if AL Agent installed
def who_is_missing(phost_data, asset_data):
    phost_list = []
    message = ""
    for phost in phost_data:
        phost_list.append(phost["protectedhost"]["metadata"]["ec2_instance_id"])

    for asset in asset_data:
        if asset[0]["instance_id"] not in phost_list:
            #print (asset[0]["instance_id"] + " " + asset[0]["scope_aws_vpc_id"] + " " + asset[0]["scope_aws_region"])
            message = message + str(asset[0]["instance_id"] + " " + asset[0]["scope_aws_vpc_id"] + " " + asset[0]["scope_aws_region"] + "\n\n")
            #print (json.dumps(asset[0]["tags"], indent=4))

    return message

#Get Cloud Insight assets based on given CID, ENV ID and asset query type
def get_ci_host(insight_dc, token, target_cid, env_id, asset_type):
    API_ENDPOINT = "https://api.cloudinsight" + insight_dc + "/assets/v1/" + target_cid + "/environments/" + env_id + asset_type
    REQUEST = requests.get(API_ENDPOINT, headers={'x-aims-auth-token': token}, verify=False)
    RESULT = json.loads(REQUEST.text)
    return RESULT

#Get Cloud Defender asset based on given CID and asset query type
def get_cd_phost(defender_dc, target_cid, target_aws, asset_type):
    API_ENDPOINT = "https://publicapi" + defender_dc + "/api/tm/v1/" + target_cid + "/" + asset_type
    REQUEST = requests.get(API_ENDPOINT, headers=CD_HEADERS, auth=(API_KEY,''))
    RESULT = json.loads(REQUEST.text)
    #Filter based on AWS account number
    FILTER_RESULT = [phost for phost in RESULT["protectedhosts"] if "ec2_account_id" in phost["protectedhost"]["metadata"] and phost["protectedhost"]["metadata"]["ec2_account_id"] == target_aws]
    return FILTER_RESULT

#Authenticate with CI yarp to get token
def authenticate(user, paswd,yarp):
    url = yarp
    user = user
    password = paswd
    r = requests.post('https://{0}/aims/v1/authenticate'.format(url), auth=(user, password), verify=False)
    if r.status_code != 200:
        sys.exit("Unable to authenticate %s" % (r.status_code))
    account_id = json.loads(r.text)['authentication']['user']['account_id']
    token = r.json()['authentication']['token']
    return token
