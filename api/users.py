import os
import json
import logging
import uuid
import time
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
# import bcrypt
# import jwt

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')


# create user
def create_user(event, context):
    data = event['user']
    
    if 'username' not in data:
        logging.error("Validation Failed")
        raise Exception("Username must be specified.", 422)
    if 'email' not in data:
        logging.error("Validation Failed")
        raise Exception("Email must be specified.", 422)
    if 'password' not in data:
        logging.error("Validation Failed")
        raise Exception("Password must be specified.", 422)

    timestamp = str(datetime.utcnow().timestamp())

    table = dynamodb.Table('dev-users')

    # Verify username is not taken
    user_exists = check_username_exists(data['username'])
    if 'Item' not in user_exists:
        pass
    else:
        logging.error("Validation Failed")
        raise Exception(f"Username already taken: {data['username']}", 422)

    # Verify email is not taken
    email_exists = check_email_exists(data['email'])
    if email_exists['Count'] != 0:
        logging.error("Validation Failed")
        raise Exception(f"Email already taken: {data['email']}", 422)

    # password = data['password'].encode()
    # hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    # encoded = jwt.encode({'token': data['username']}, 'secret', algorithm='HS256')
    item = {
        # 'id': str(uuid.uuid1()),
        # 'id': data['id'],
        'username': data['username'],
        'email': data['email'],
        'password': data['password'],
        'createdAt': timestamp,
        'updatedAt': timestamp
    }

    # create the user to the database
    table.put_item(Item=item)
    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6ImdhdXRhbSJ9.5CLsX4nOuTagsC6nSGWfq-4oZZAL0RhlMLOm7QMGy_Q'
    body = {
        'user': {
            'email': data['email'],
            'token': token,
            'username': data['username'],
            'bio': '',
            'image': '',
        }
    }
    # create a response
    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": body
    }

    return response


def check_username_exists(username):
    table = dynamodb.Table('dev-users')

    try:
        response = table.get_item(
            Key={
                'username': username
            }
        )
    except Exception as e:
        response = None
    print(f"RESP:{response}")
    return response


def check_email_exists(aemail):
    table = dynamodb.Table('dev-users')
    print(aemail)
    response = table.query(
        IndexName='email',
        KeyConditionExpression='email= :email',
        ExpressionAttributeValues={
            ':email': aemail,
        },
        Select='ALL_ATTRIBUTES',
    )
    print(f"EMAIL:{response}")
    return response


# login user
def login_user(event, context):
    data = event['user']
    if not data:
        logging.error("Validation Failed")
        raise Exception("User must be specified.", 422)
    if 'email' not in data:
        logging.error("Validation Failed")
        raise Exception("Email must be specified.", 422)
    if 'password' not in data:
        logging.error("Validation Failed")
        raise Exception("Password must be specified.", 422)

    # Get user with this email
    get_user_with_this_email = check_email_exists(data['email'])
    if get_user_with_this_email['Count'] != 1:
        logging.error("Validation Failed")
        raise Exception(f"Email not fount: {data['email']}.", 422)

    if get_user_with_this_email['Items'][0]['password'] != data['password']:
        raise Exception("Wrong password.", 422)

    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6ImdhdXRhbSJ9.5CLsX4nOuTagsC6nSGWfq-4oZZAL0RhlMLOm7QMGy_Q'

    authenticated_user = {
        'user': {
            'email': data['email'],
            'token': token,
            'username': get_user_with_this_email['Items'][0]['username']
            # 'bio': get_user_with_this_email['Items'][0]['bio'] | '',
            # 'image': get_user_with_this_email['Items'][0]['image'] | ''
        }
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": authenticated_user
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
