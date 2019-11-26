import boto3
import time
from os import path, chmod
from botocore.exceptions import ClientError


ec2 = boto3.client('ec2')
ec2r = boto3.resource('ec2')
elbv = boto3.client('elbv2')
autoscaling = boto3.client('autoscaling')
ubuntu_east1 = 'ami-04b9e92b5572fa0d1'


# DB
ec2db = boto3.client('ec2', region_name="us-east-2")
ec2rdb = boto3.resource('ec2', region_name="us-east-2")
ubuntu_east2 = 'ami-0d5d9d301c853a04a'


keyName = 'virginia'
keyName2 = 'ohio'
securityGroupName = 'Arthur-SG'
targetGroupName = 'Arthur-target-group'
loadBalancerName = 'arthur-load-balancer'
launch_config_name = 'arthur-launch-configuration'
autoscaling_name = 'arthur-autoscaling-group'


dbPath = ""
wsPath = ""


def redirect_data(path):
    user_data = '''#! /bin/bash
    sudo apt-get update
    sudo apt-get -y install python3-pip
    pip3 install flask
    pip3 install flask_restful
    pip3 install flask_httpauth
    pip3 install flask_pymongo
    cd home/ubuntu
    git clone https://github.com/arthurolga/ProjetoCloud
    cd ProjetoCloud/RedirectServer/
    echo "teste" > teste.txt
    echo "export NEW_URL=http://{}:5000" > redirect.rc
    source redirect.rc
    python3 redirect.py
        '''.format(path)
    return user_data


def server_data(path):
    user_data = '''#! /bin/bash
    sudo apt-get update
    sudo apt-get -y install python3-pip
    pip3 install flask
    pip3 install flask_restful
    pip3 install flask_httpauth
    pip3 install flask_pymongo
    cd home/ubuntu
    git clone https://github.com/arthurolga/ProjetoCloud
    cd ProjetoCloud/Server/
    echo "export DB=mongodb://{}:5000/tasks" > server.rc
    source server.rc
    python3 server.py
        '''.format(path)
    return user_data


user_data_db = '''#! /bin/bash
sudo apt-get install gnupg
wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list
sudo apt-get update
sudo apt-get install -y mongodb-org
sudo -i
sed -i 's/port: 27017/port: 5000/' /etc/mongod.conf
sed -i 's/bindIp: 127.0.0.1/bindIp: 0.0.0.0/' /etc/mongod.conf
sudo service mongod start
    '''


ownerName = 'Arthur'

# KEYPAIR


def create_key_pair(client, keyName):
    try:
        response = client.describe_key_pairs(
            KeyNames=[keyName]
        )
        client.delete_key_pair(KeyName=keyName)
    except ClientError as e:
        print(e)

    print("Creating Key Pair")
    r = client.create_key_pair(
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


def create_security_group(client, open=True):  # ec2
    vpcs = client.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]

    try:
        client.delete_security_group(GroupName=securityGroupName)
    except ClientError as e:
        print(e)

    print("Creating Security Group")
    securitygroup = client.create_security_group(
        Description='SecurityGroup Arthur',
        GroupName=securityGroupName,
        VpcId=vpc_id
    )

    permissions = [{
        'FromPort': 22,
        'IpProtocol': 'TCP',
        'IpRanges': [
            {
                'CidrIp': '0.0.0.0/0',
                'Description': 'Porta pra SSH'
            },
        ],
        'ToPort': 22
    }]

    if open:
        permissions.append({
            'FromPort': 5000,
            'IpProtocol': 'TCP',
            'IpRanges': [
                {
                    'CidrIp': '0.0.0.0/0',
                    'Description': 'Porta para Server'
                },
            ],
            'ToPort': 5000
        })

    client.authorize_security_group_ingress(
        GroupId=securitygroup["GroupId"],
        IpPermissions=permissions
    )
    # print(securitygroup["GroupId"])
    return securitygroup
# Instancia


def delete_all_instances(client, resource, tag, value):
    response = client.describe_instances(
        Filters=[
            {
                'Name': 'tag:'+tag,
                'Values': [
                    value
                ]
            },
        ])
    # print(response["Reservations"][0]['Instances'][0]['State']['Name'])
    try_delete = None
    reservations = response["Reservations"]  # [0]['Instances']

    for reservation in reservations:
        for inst in reservation['Instances']:
            # print(inst['State']['Name'])
            if (inst['State']['Name'] != 'terminated'):
                try_delete = True

    if try_delete:
        try:
            instances = resource.instances.filter(
                Filters=[
                    {
                        'Name': 'tag:'+tag,
                        'Values': [
                            value,
                        ]
                    },
                ],
            )
            print(">>>>> DELETANDOOOO")
            instances.terminate()
            waiter = client.get_waiter('instance_terminated')
            waiter.wait(
                Filters=[{
                    'Name': 'tag:'+tag,
                    'Values': [value]
                }, ])

        except ClientError as e:
            print(e)


def create_instances(client, resource, keyName, securitygroupId, imageId, udata, name="Instance", num=1):  # ec2 e ec2r
    instance = resource.create_instances(
        ImageId=imageId,
        KeyName=keyName,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': ownerName+"-"+name
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
        UserData=udata,
        DryRun=False,
        SecurityGroupIds=[
            securitygroupId  # securitygroup["GroupId"]
        ]
    )
    # print(instance)

    ids = []
    for i in instance:
        ids.append(i.id)

    # Wait
    waiter_instance = client.get_waiter("instance_status_ok")
    waiter_instance.wait(
        InstanceIds=ids
    )

    return instance


def create_target_group(client, elbv, name):  # ec2 elbv
    vpcs = client.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]

    response = elbv.create_target_group(
        Name='Arthur-target-group',
        Protocol='HTTP',
        Port=5000,
        VpcId=vpc_id,
        HealthCheckProtocol='HTTP',
        HealthCheckEnabled=True,
        HealthCheckPath='/check',
        TargetType='instance'
    )

    # print(response)
    return response


def delete_target_group(name):
    try:
        response = elbv.describe_target_groups(
            Names=[
                name,
            ]
        )
        # if response['TargetGroups']
        for i in response['TargetGroups']:
            response = elbv.delete_target_group(
                TargetGroupArn=i['TargetGroupArn']
            )
    except:
        print("No target Group")


def create_load_balancer(name, securityId):
    response = elbv.create_load_balancer(
        Name=loadBalancerName,
        SecurityGroups=[
            securityId,
        ],
        Subnets=['subnet-1c813340',
                 'subnet-4999d803',
                 'subnet-540e795b',
                 'subnet-5ddb6b3a',
                 'subnet-91a463af',
                 'subnet-d164d8ff'],
        Scheme='internet-facing',
        Tags=[
            {
                'Key': 'Owner',
                'Value': ownerName
            },
        ],
        Type='application',
        IpAddressType='ipv4'
    )

    # print(response["LoadBalancers"][0])

    # Wait
    waiter_instance = elbv.get_waiter("load_balancer_available")
    waiter_instance.wait(
        Names=[name]
    )
    time.sleep(20)


def delete_load_balancer(name):
    try:
        response = elbv.describe_load_balancers(
            Names=[name]
        )

        # print(response['LoadBalancers'])
        for l in response['LoadBalancers']:
            # print(l['LoadBalancerArn'])
            response = elbv.delete_load_balancer(
                LoadBalancerArn=l['LoadBalancerArn']
            )
            # Wait
            waiter_instance = elbv.get_waiter("load_balancers_deleted")
            waiter_instance.wait(
                LoadBalancerArns=[l['LoadBalancerArn']]
            )
            time.sleep(20)
    except:
        print("No Load balancer")


def create_launch_configuration(client, user_data):
    response = client.create_launch_configuration(
        LaunchConfigurationName=launch_config_name,
        ImageId='ami-04b9e92b5572fa0d1',
        KeyName=keyName,
        SecurityGroups=[
            securityGroupName
        ],
        UserData=user_data,
        InstanceType='t2.micro'
    )

    return response


def delete_launch_configuration(client):
    try:
        response = client.delete_launch_configuration(
            LaunchConfigurationName=launch_config_name
        )
    except ClientError as e:
        print(e)


def create_auto_scaling_group(client, targetGroup):
    response = client.create_auto_scaling_group(
        AutoScalingGroupName=autoscaling_name,
        LaunchConfigurationName=launch_config_name,
        MinSize=1,
        MaxSize=3,
        # LoadBalancerNames=[
        #     loadBalancerName
        # ],
        TargetGroupARNs=[
            targetGroup["TargetGroups"][0]["TargetGroupArn"]
        ],
        AvailabilityZones=[
            'us-east-1a', 'us-east-1b', 'us-east-1c', 'us-east-1d', 'us-east-1e', 'us-east-1f'
        ]
    )

    print(">>>>> AutoScalingGroup: ", response)

    response = ec2.describe_instances(
        Filters=[
            {
                'Name': 'tag:aws:autoscaling:groupName',
                'Values': [autoscaling_name]
            },
        ])

    print(response)
    print(">>>>>>> Instances OK")

    return response


def delete_auto_scaling_group(client, autoscaling_name):
    try:
        client.delete_auto_scaling_group(
            AutoScalingGroupName=autoscaling_name,
            ForceDelete=True
        )
        custom_waiter_deleted_auto_scaling(client, autoscaling_name)
        waiter = ec2.get_waiter('instance_terminated')
        waiter.wait(
            Filters=[{
                'Name': 'tag:aws:autoscaling:groupName',
                'Values': [autoscaling_name]
            }, ])

    except:
        print("No AutoScalingGroup")


def custom_waiter_deleted_auto_scaling(client, name):
    while True:
        r = client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[name])['AutoScalingGroups']
        time.sleep(5)
        print("Deletando AutoScaling Group")
        if len(r) == 0:
            break


def register_targets(client, targetGroupArn, loadBalancerName):
    # try:
    instances = ec2r.instances.filter(
        Filters=[
            {
                'Name': 'tag:aws:autoscaling:groupName',
                'Values': [
                    autoscaling_name,
                ]
            },
        ],
    )
    # print(instances)
    targetDicts = []
    for i in instances:
        print(i, i.state)
        if (i.state['Name'] == "running"):
            parse = {'Id': i.id,
                     'Port': 5000, }
            targetDicts.append(parse)

    print(">>> TagetDicts", targetDicts)

    if targetDicts != []:
        client.register_targets(
            TargetGroupArn=targetGroupArn,
            Targets=targetDicts)

    loadBalancerARN = client.describe_load_balancers(
        Names=[loadBalancerName])["LoadBalancers"][0]['LoadBalancerArn']

    client.create_listener(
        DefaultActions=[
            {
                # targetGroup["TargetGroups"][0]["TargetGroupArn"],
                'TargetGroupArn': targetGroupArn,
                'Type': 'forward',
            }, ],
        LoadBalancerArn=loadBalancerARN,
        Port=5000,
        Protocol='HTTP',
    )


def edit_authorization(client, securityGroupName, dns):
    response = client.authorize_security_group_ingress(
        GroupName=securityGroupName,
        # GroupId="sg-037ca28dda16a98e6"
        IpPermissions=[
            {
                'FromPort': 5000,
                'IpProtocol': 'TCP',
                'IpRanges': [
                    {
                        'CidrIp': dns+'/32',
                        'Description': 'Porta para aceitar o Server de Virginia'
                    },
                ],
                'ToPort': 5000
            }
        ]
    )


def print_step(int):
    lista = [' ', ' ', ' ', ' ', ' ', ' ']
    for i in range(int):
        lista[i] = 'X'

    print(''''
/North Virginia                                      /Ohio
+--------------------------------------------------+ +--------------------------------------+
|                                                  | |                                      |
|                      +--------+                  | |                                      |
|                      |        |                  | |                                      |
|    +--------+        |        |   +------------+ | |         +-----------+     +-------+  |
|    |        |        |  ASG   |   |            | | |         |           |     |       |  |
|    |  LB    +--------+        +---+  Redirect  +-------------+ webserver +-----+mongodb|  |
|    |      '''+lista[4]+''' |        |        |   |        '''+lista[2]+'''   | | |         |       '''+lista[1]+'''   |     |    '''+lista[0]+'''  |  |
|    +--------+        |      '''+lista[3]+''' |   +------------+ | |         +-----------+     +-------+  |
|                      +--------+                  | |                                      |
|                                                  | |                                      |
+--------------------------------------------------+ +--------------------------------------+
    ''')


def create_ohio():
    delete_all_instances(ec2db, ec2rdb, "Owner", ownerName)
    create_key_pair(ec2db, keyName2)
    sgroup = create_security_group(ec2db, open=False)

    # MongoDB
    db = create_instances(ec2db, ec2rdb, keyName2, sgroup["GroupId"],
                          ubuntu_east2, user_data_db, name="Mongo-Database")

    db[0].load()
    db_dns = db[0].public_dns_name
    print_step(1)
    print("MongoDB Public DNS", db_dns)

    # WebServer
    ws = create_instances(ec2db, ec2rdb, keyName2, sgroup["GroupId"],
                          ubuntu_east2, server_data(db_dns), name="WebServer")

    ws[0].load()
    ws_dns = ws[0].public_dns_name
    ws_pv = ws[0].private_ip_address
    print_step(2)
    print("WebServer Ohio Public DNS", ws_dns)

    # Authorizing WebServer
    edit_authorization(ec2db, securityGroupName, ws_pv)

    global dbPath
    dbPath = str(db_dns)

    global wsPath
    wsPath = str(ws_dns)


def create_virginia():
    delete_all_instances(ec2, ec2r, "Owner", ownerName)
    delete_all_instances(
        ec2, ec2r, "aws:autoscaling:groupName", autoscaling_name)

    delete_auto_scaling_group(autoscaling, autoscaling_name)
    delete_target_group(targetGroupName)
    delete_load_balancer(loadBalancerName)
    delete_launch_configuration(autoscaling)

    create_key_pair(ec2, keyName)
    sgroup = create_security_group(ec2)

    # Redirect Instance
    red = create_instances(ec2, ec2r, keyName, sgroup["GroupId"],
                           ubuntu_east1, redirect_data(wsPath), name="Redirect-Server")

    red[0].load()
    red_dns = red[0].public_dns_name
    red_ip = red[0].public_ip_address
    print_step(3)
    print("Redirect Server Public DNS", red_dns)

    create_load_balancer(loadBalancerName, sgroup["GroupId"])

    #instances = create_instances(ec2, ec2r, sgroup, udata=user_data)

    tg = create_target_group(ec2, elbv, targetGroupName)
    tgARN = tg["TargetGroups"][0]["TargetGroupArn"]

    # server_data(dbPath))
    create_launch_configuration(autoscaling,  redirect_data(red_dns))

    auto_group = create_auto_scaling_group(autoscaling, tg)

    print("Auto Scaling Group", auto_group)

    register_targets(elbv, tgARN, loadBalancerName)
    print_step(5)

    print("Authorizing Ohio")
    edit_authorization(ec2db, securityGroupName, red_ip)


if __name__ == '__main__':
    print(''''
/North Virginia                                      /Ohio
+--------------------------------------------------+ +--------------------------------------+
|                                                  | |                                      |
|                      +--------+                  | |                                      |
|                      |        |                  | |                                      |
|    +--------+        |        |   +------------+ | |         +-----------+     +-------+  |
|    |        |        |  ASG   |   |            | | |         |           |     |       |  |
|    |  LB    +--------+        +---+  Redirect  +-------------+ webserver +-----+mongodb|  |
|    |        |        |        |   |            | | |         |           |     |       |  |
|    +--------+        |        |   +------------+ | |         +-----------+     +-------+  |
|                      +--------+                  | |                                      |
|                                                  | |                                      |
+--------------------------------------------------+ +--------------------------------------+


    ''')
    print("   Creating Ohio ....")
    create_ohio()
    print("   Ohio Successfully Created!")

    print("   Creating Virginia ....")
    create_virginia()
    print("   Virginia Successfully Created!")

    print(securityGroupName)

    print(">>>>>> DONE ~~")
    print('\a')
    time.sleep(0.2)
    print('\a')
    time.sleep(0.2)
    print('\a')
    time.sleep(0.1)
    print('\a')
    time.sleep(0.1)
