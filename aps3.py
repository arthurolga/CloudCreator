import boto3
from os import path, chmod
from botocore.exceptions import ClientError


ec2 = boto3.client('ec2')
ec2r = boto3.resource('ec2')


keyName = 'teste'
securityGroupName = 'APS Arthur'

user_data = '''#!/bin/bash
git clone https://github.com/arthurolga/ProjetoCloud'''

# KEYPAIR


def create_key_pair():
    try:
        response = ec2.describe_key_pairs(
            KeyNames=[keyName]
        )
        ec2.delete_key_pair(KeyName=keyName)
    except ClientError as e:
        print(e)

    print("Creating Key Pair")
    r = ec2.create_key_pair(
        KeyName=keyName
    )

    keyPath = keyName+".pem"

    if (path.exists(keyPath)):
        print("Mudando permissao da KeyFile")
        chmod(keyPath, 0o777)

    with open(keyPath, "w+") as fh:
        # Escrevendo na KeyPair
        print("Escrevendo na KeyFile")
        fh.write(r["KeyMaterial"])

    chmod(keyPath, 0o400)


# Security Group


def create_security_group():
    vpcs = ec2.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]

    try:
        ec2.describe_security_groups(GroupNames=[securityGroupName])
        ec2.delete_security_group(GroupName=securityGroupName)
    except ClientError as e:
        print(e)

    print("Creating Security Group")
    securitygroup = ec2.create_security_group(
        Description='SecurityGroup Arthur',
        GroupName=securityGroupName,
        VpcId=vpc_id
    )

    print(securitygroup)

    ec2.authorize_security_group_ingress(
        GroupId=securitygroup["GroupId"],
        IpPermissions=[
            {
                'FromPort': 5000,
                'IpProtocol': 'TCP',
                'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'Porta pro Server'
                    },
                ],
                'ToPort': 5000
            },
            {
                'FromPort': 22,
                'IpProtocol': 'TCP',
                'IpRanges': [
                    {
                        'CidrIp': '0.0.0.0/0',
                        'Description': 'Porta pra SSH'
                    },
                ],
                'ToPort': 22
            }
        ]
    )
    print(securitygroup["GroupId"])
    return securitygroup
# Instancia


def delete_all_instances():
    try:
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Owner',
                    'Values': [
                        'Arthur',
                    ]
                },
            ])
        print(response)
        instance = ec2r.instances.filter(
            Filters=[
                {
                    'Name': 'tag:Owner',
                    'Values': [
                        'Arthur',
                    ]
                },
            ],
        )
        print(instance)
        # instance.terminate()
    except ClientError as e:
        print(e)


def create_instances(securitygroup, num=1):
    instance = ec2r.create_instances(
        ImageId='ami-04b9e92b5572fa0d1',
        KeyName=keyName,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': 'APS3 - Arthur'
                    },
                    {
                        'Key': 'Owner',
                        'Value': 'Arthur'
                    }
                ]
            },
        ],
        InstanceType='t2.micro',
        MinCount=1,
        MaxCount=num,
        UserData=user_data,
        SecurityGroupIds=[
            securitygroup["GroupId"]
        ]
    )
    print(instance)
    return instance


if __name__ == '__main__':
    # delete_all_instances()
    create_key_pair()
    sgroup = create_security_group()
    instances = create_instances(sgroup)

    ids = []
    for i in instances:
        ids.append(i.id)

    # Wait
    waiter_instance = ec2.get_waiter("instance_running")
    waiter_instance.wait(
        InstanceIds=ids
    )
    print(">>>>>>Criou")

# mkdir server
# cd server/
# git clone https://github.com/arthurolga/ProjetoCloud
# cd ProjetoCloud/APS1
# sudo apt update
# sudo apt install python3-pip
# Y
# pip3 install flask
# pip3 install flask_restful
# pip3 install flask_httpauth


#waiterInstance = ec2.get_waiter()
