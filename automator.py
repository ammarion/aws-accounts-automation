#!/usr/bin/env python3

"""python3 create_account.py --account_name ate-io-product54 --account_email ate-io-product54@pearson.com"""

import boto3
import botocore
import time
import sys
import argparse

'''
AWS Organizations Create Account and Provision Resources via CloudFormation
This module creates a new account using Organizations,
then calls CloudFormation to deploy custom resources within that
account via a local template file.
'''

session = boto3.Session(profile_name='master')


def create_account(
        account_name,
        account_email,
        account_role,
        access_to_billing,
        organization_unit_id,
        scp):

    """Create a new AWS account and add it to an organization"""

    client = session.client('organizations')

    try:
        create_account_response = client.create_account(Email=account_email, AccountName=account_name,
                                                        RoleName=account_role,
                                                        IamUserAccessToBilling=access_to_billing)
    except botocore.exceptions.ClientError as e:
        print(e)
        sys.exit(1)

    time.sleep(10)

    account_status = 'IN_PROGRESS'
    while account_status == 'IN_PROGRESS':
        create_account_status_response = client.describe_create_account_status(
            CreateAccountRequestId=create_account_response.get('CreateAccountStatus').get('Id'))
        print("Create account status "+str(create_account_status_response))
        account_status = create_account_status_response.get('CreateAccountStatus').get('State')
    if account_status == 'SUCCEEDED':
        accountid = create_account_status_response.get('CreateAccountStatus').get('AccountId')
    elif account_status == 'FAILED':
        print("Account creation failed: " + create_account_status_response.get('CreateAccountStatus').get('FailureReason'))
        sys.exit(1)
    root_id = client.list_roots().get('Roots')[0].get('Id')

    # Move account to the org
    if organization_unit_id is not None:
        try:
            describe_organization_response = client.describe_organizational_unit(
                OrganizationalUnitId=organization_unit_id)
            move_account_response = client.move_account(AccountId=accountid, SourceParentId=root_id,
                                                        DestinationParentId=organization_unit_id)
        except Exception as ex:
            template = "An exception of type {0} occurred. Arguments:\n{1!r} "
            message = template.format(type(ex).__name__, ex.args)
            # create_organizational_unit(organization_unit_id)
            print(message)

    # Attach policy to account if exists
    if scp is not None:
        attach_policy_response = client.attach_policy(PolicyId=scp, TargetId=accountid)
        print("Attach policy response "+str(attach_policy_response))

    return accountid


def assume_role(accountid, account_role):

    """"
        Assume admin role within the newly created account and return credentials
    """

    sts_client = session.client('sts')
    role_arn = 'arn:aws:iam::' + accountid + ':role/' + account_role

    # Call the assume_role method of the STSConnection object and pass the role
    # ARN and a role session name.

    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            print(e)
            print("Retrying...")
            time.sleep(10)

    # From the response that contains the assumed role, get the temporary
    # credentials that can be used to make subsequent API calls
    return assumedRoleObject['Credentials']


def put_public_access_block(credentials, account):
    """Creates or modifies the Public Access Block configuration for an Amazon Web Services account."""
    control = boto3.client('s3control',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'])
    control.put_public_access_block(
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        },
        AccountId=account
    )


def get_template(template_file):

    '''
        Read a template file and return the contents
    '''

    print("Reading resources from " + template_file)
    f = open(template_file, "r")
    cf_template = f.read()
    return cf_template


def deploy_resources(credentials, template, stack_name, stack_region, SNSfriendlyname, SNSemail, SNSdescription):

    """
        Create a CloudFormation stack of resources within the new account
    """

    datestamp = time.strftime("%d/%m/%Y")
    client = boto3.client('cloudformation',
                          aws_access_key_id=credentials['AccessKeyId'],
                          aws_secret_access_key=credentials['SecretAccessKey'],
                          aws_session_token=credentials['SessionToken'],
                          region_name=stack_region)
    print("Creating stack " + stack_name + " in " + stack_region)

    creating_stack = True
    while creating_stack is True:
        try:
            creating_stack = False
            create_stack_response = client.create_stack(
                StackName=stack_name,
                TemplateBody=template,
                Parameters=[
                    {
                        'ParameterKey': 'SNSfriendlyname',
                        'ParameterValue': SNSfriendlyname
                    },

                    {
                        'ParameterKey': 'SNSemail',
                        'ParameterValue': SNSemail
                    },
                    {
                        'ParameterKey': 'SNSdescription',
                        'ParameterValue': SNSdescription
                    }
                ],
                NotificationARNs=[],
                Capabilities=[
                    'CAPABILITY_NAMED_IAM',
                ],
                OnFailure='ROLLBACK',
                Tags=[
                    {
                        'Key': 'ManagedResource',
                        'Value': 'True'
                    },
                    {
                        'Key': 'DeployDate',
                        'Value': datestamp
                    }
                ]
            )
        except botocore.exceptions.ClientError as e:
            creating_stack = True
            print(e)
            print("Retrying...")
            time.sleep(10)

    stack_building = True
    print("Stack creation in process...")
    print(create_stack_response)
    while stack_building is True:
        event_list = client.describe_stack_events(StackName=stack_name).get("StackEvents")
        stack_event = event_list[0]

        if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
           stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
            stack_building = False
            print("Stack construction complete.")
        elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
              stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
            stack_building = False
            print("Stack construction failed.")
            sys.exit(1)
        else:
            print(stack_event)
            print("Stack building . . .")
            time.sleep(10)

    stack = client.describe_stacks(StackName=stack_name)
    return stack


def main(arguments):

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--account_name', required=True)
    parser.add_argument('--account_email', required=True)
    parser.add_argument('--account_role',
                        default='OrganizationAccountAccessRole')
    parser.add_argument('--template_file',
                        default='admin.yml')
    parser.add_argument('--stack_name',
                        default='admin-bootstrap')
    parser.add_argument('--stack_region',
                        default='us-east-1')
    # parser.add_argument('--SNSfriendlyname', required=True)
    # parser.add_argument('--SNSemail', required=True)
    # parser.add_argument('--SNSdescription', required=True)
    args = parser.parse_args(arguments)

    access_to_billing = "ALLOW"
    organization_unit_id = None
    scp = None

    print("Creating new account: " + args.account_name + " (" + args.account_email + ")")
    #accountid = create_account(args.account_name, args.account_email, args.account_role,access_to_billing, organization_unit_id, scp)
    """" Comment the above line and uncomment the below line to skip 
     account creation and just test Cfn deployment (for testing)"""
    accountid = "099252316056"
    print("Created acount: " + accountid)
    credentials = assume_role(accountid, args.account_role)
    print("Set Public Access Block configuration on account : " + accountid)
    put_public_access_block(credentials, account=accountid)
    print("Deploying resources from " + args.template_file + " as " + args.stack_name + " in " + args.stack_region)
    template = get_template(args.template_file)
    stack = deploy_resources(credentials, template, args.stack_name, args.stack_region, args.account_name,
                             args.account_email, args.account_name)
    print(stack)
    print("Resources deployed for account " + accountid + " (" + args.account_email + ")")

    # Enable enterprise support

    def enable_enterpris():
        client = session.client('support')

        response = client.create_case(
            subject='Enable Enterprise Support Plan',
            serviceCode='customer-account',
            severityCode='normal',
            categoryCode='activation',
            communicationBody='Hello AWS, please enable the Enterprise Support Plan for account {}\
            which is a member of our Organization'.format(accountid),
            ccEmailAddresses=[
                'ammar.alim@pearson.com', 'ate-io-finops@pearson.com',
            ],
            language='en',
            issueType='customer-service'
        )
        print(response)



    def assume_role_iam_pearson():

        """
            Assume admin role within the Pearson-IAM account and return credentials
        """
        s = boto3.Session(profile_name='pearson')
        sts_client = s.client('sts')
        role_arn = 'arn:aws:iam::812653090533:role/managed-role/PearsonAdmin'

        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name.

        assuming_role = True
        while assuming_role is True:
            try:
                assuming_role = False
                assumedroleobject = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="IAM-PearsonAccountRole"
                )
            except botocore.exceptions.ClientError as e:
                assuming_role = True
                print(e)
                print("Retrying...")
                time.sleep(10)

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls
        return assumedroleobject['Credentials']

    # Create groups in iam-pearson account

    def get_groups_template(template_groups_file):

        """
            Read a template file and return the contents
        """

        print("Reading resources from " + template_groups_file)
        f = open(template_groups_file, "r")
        iam_groups_template = f.read()
        return iam_groups_template

    def deploy_groups(credentials, template, stack_name, stack_region, AWSAccountNumber):

        """
            Create a CloudFormation stack of resources within the new account
        """

        datestamp = time.strftime("%d/%m/%Y")
        client = boto3.client('cloudformation',
                              aws_access_key_id=credentials['AccessKeyId'],
                              aws_secret_access_key=credentials['SecretAccessKey'],
                              aws_session_token=credentials['SessionToken'],
                              region_name=stack_region)
        print("Creating stack " + stack_name + " in " + stack_region)

        creating_stack = True
        while creating_stack is True:
            try:
                creating_stack = False
                create_stack_response = client.create_stack(
                    StackName=stack_name,
                    TemplateBody=template,
                    Parameters=[
                        {
                            'ParameterKey': 'AWSAccountNumber',
                            'ParameterValue': accountid,
                            'UsePreviousValue': False
                        },

                    ],
                    NotificationARNs=[],
                    Capabilities=[
                        'CAPABILITY_NAMED_IAM',
                    ],
                    OnFailure='ROLLBACK',
                    Tags=[
                        {
                            'Key': 'ManagedResource',
                            'Value': 'True'
                        },
                        {
                            'Key': 'DeployDate',
                            'Value': datestamp
                        }
                    ]
                )
            except botocore.exceptions.ClientError as e:
                creating_stack = True
                print(e)
                print("Retrying...")
                time.sleep(30)

        stack_building = True
        print("Stack creation in process...")
        print(create_stack_response)
        while stack_building is True:
            event_list = client.describe_stack_events(StackName=stack_name).get("StackEvents")
            stack_event = event_list[0]

            if (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                    stack_event.get('ResourceStatus') == 'CREATE_COMPLETE'):
                stack_building = False
                print("Stack construction complete.")
            elif (stack_event.get('ResourceType') == 'AWS::CloudFormation::Stack' and
                  stack_event.get('ResourceStatus') == 'ROLLBACK_COMPLETE'):
                stack_building = False
                print("Stack construction failed.")
                sys.exit(1)
            else:
                print(stack_event)
                print("Stack building . . .")
                time.sleep(10)

        stack = client.describe_stacks(StackName=stack_name)
        return stack

    enable_enterpris()
    credential = assume_role_iam_pearson()
    groups_template = get_groups_template('groups.yml')
    deploy_groups(credential, template=groups_template, stack_name='pearson-iam-groups-' + accountid,
                  stack_region='us-east-1', AWSAccountNumber=accountid)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
