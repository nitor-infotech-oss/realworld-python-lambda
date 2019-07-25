import os
import json
import logging
import uuid
import time
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
import boto3

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')


# create user
def create_user(event, context):
    # data = json.loads(event['body'])
    if 'username' not in event:
        logging.error("Validation Failed")
        raise Exception("User must be specified.", 422)
    if 'email' not in event:
        logging.error("Validation Failed")
        raise Exception("Email must be specified.", 422)
    if 'password' not in event:
        logging.error("Validation Failed")
        raise Exception("Password must be specified.", 422)

    timestamp = str(datetime.utcnow().timestamp())

    table = dynamodb.Table('users')

    item = {
        'id': str(uuid.uuid1()),
        'username': event['username'],
        'email': event['email'],
        'password': event['password'],
        'createdAt': timestamp,
        'updatedAt': timestamp
    }

    # create the user to the database
    table.put_item(Item=item)

    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(item)
    }

    return response


# login user
def login_user(event, context):
    username = event['username']
    password = event['password']
    table = dynamodb.Table('users')
    result = table.scan(
        FilterExpression=Attr('username').eq(username) & Attr('password').eq(password)
    )

    if result['Items']:
        message = {"msg": "Login success", "data": result['Items']}
    else:
        message = "Login Failed"

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": json.dumps(message)
    }
    return response


# get user
def get_user(event, context):
    table = dynamodb.Table('users')
    result = table.scan()

    # create a response
    response = {
        "statusCode": 200,
        "body": json.dumps(result['Items'])
    }

    return response


def update_user(event, context):
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
