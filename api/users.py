import os
import json
import logging
import uuid
import time
from datetime import datetime
import boto3

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')


# create user
def createUser(event, context):
    print(event)
    print('context', context)
    data = json.loads(event['body'])
    if 'username' not in data:
        logging.error("Validation Failed")
        raise Exception("User must be specified.", 422)
    if 'email' not in data:
        logging.error("Validation Failed")
        raise Exception("Email must be specified.", 422)
    if 'password' not in data:
        logging.error("Validation Failed")
        raise Exception("Password must be specified.", 422)

    table = dynamodb.Table('users')

    item = {
        'id': str(uuid.uuid1()),
        'username': data['username'],
        'email': data['email'],
        'password': data['password']
    }

    # create the user to the database
    table.put_item(Item=item)

    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(item)
    }

    return response


# get user
def getUser(event, context):
    table = dynamodb.Table('users')
    result = table.scan()

    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(result['Items'])
    }

    return response


def updateUser(event, context):
    data = json.loads(event['body'])
    if 'username' not in data or 'password' not in data:
        logging.error("Validation Failed")
        raise Exception("Couldn't update the user.")
        return

    table = dynamodb.Table('users')

    # update the user in the database
    result = table.update_item(
        Key={
            'id': data['id'],
            'username': data['username']

        },
        ExpressionAttributeNames={
            '#email': 'email',
        },
        ExpressionAttributeValues={
            ':email': data['email'],
            ':password': data['password']
        },
        UpdateExpression='SET #email = :email, '
                         'password = :password',
        ReturnValues='ALL_NEW',
    )

    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(result['Attributes'])
    }

    return response
