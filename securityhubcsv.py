import boto3
from botocore import exceptions

s = boto3.Session(profile_name='master')

org = s.client('organizations')


def list_accounts():

    response = org.list_accounts()
    for i in (response['Accounts']):
        print(i['Id']+',', i['Email'])


list_accounts()
