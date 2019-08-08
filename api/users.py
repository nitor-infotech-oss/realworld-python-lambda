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
    user_exists = get_user_by_username(data['username'])
    if 'Item' not in user_exists:
        pass
    else:
        logging.error("Validation Failed")
        raise Exception(f"Username already taken: {data['username']}", 422)

    # Verify email is not taken
    email_exists = get_user_by_email(data['email'])
    if email_exists['Count'] != 0:
        logging.error("Validation Failed")
        raise Exception(f"Email already taken: {data['email']}", 422)

    # password = data['password'].encode()
    # hashed = bcrypt.hashpw(password, bcrypt.gensalt())
    # encoded = jwt.encode({'token': data['username']}, 'secret', algorithm='HS256')
    # print(encoded)
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


def get_user_by_username(username):
    table = dynamodb.Table('dev-users')
    print(username)
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


def get_user_by_email(aemail):
    table = dynamodb.Table('dev-users')
    # print(aemail)
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
    get_user_with_this_email = get_user_by_email(data['email'])
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
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)

    body = {
        'user': {
            'email': authenticated_user['email'],
            # 'token': get_token_from_event(event, context),
            'username': authenticated_user['username']
            # 'bio': authenticatedUser.bio | | '',
            # 'image': authenticatedUser.image | | ''
        }
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": body
    }
    return response


def update_user(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    user = event
    # data = json.loads(event['body'])
    print(f"DATA: {user}")
    if not user:
        logging.error("Validation Failed")
        raise Exception("User must be specified.", 422)

    updated_user = {
        'username': authenticated_user['username']
    }

    if user['email']:
        # Verify email is not taken
        user_with_this_email = get_user_by_email(user['email'])
        if user_with_this_email['Count'] != 0:
            return Exception(f"Email already taken: {user['email']}", 422)

        updated_user['email'] = user['email']
        
    if user['password']:
        # updatedUser.password = bcrypt.hashSync(user.password, 5);
        updated_user['password'] = user['password']

    if user['image']:
        updated_user['image'] = user['image']

    if user['bio']:
        updated_user['bio'] = user['bio']   
        
    print(f"UPDATE: {updated_user}")
    
    table = dynamodb.Table('dev-users')
    table.put_item(Item=updated_user)

    if updated_user['password']:
        del updated_user['password']

    if not updated_user['email']:
        updated_user['email'] = authenticated_user['email']

    if not updated_user['image']:
        updated_user['image'] = authenticated_user['image'] if authenticated_user['image'] else ''

    if not updated_user['bio']:
        updated_user['bio'] = authenticated_user['bio'] if authenticated_user['bio'] else ''

    # updated_user['token'] = get_token_from_event(event, context)
    
    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": updated_user
    }
    
    return response


def get_token_from_event(event, context):
    pass
    # return event.headers.Authorization.replace('Token ', '')
    return event['headers']['authorization'].replace('Token', '')


def authenticate_and_get_user(event, context):
    try:
        # token = get_token_from_event(event, context)
        # decoded = jwt.verify(token, Util.tokenSecret),
        username = event['username']  # decoded.username,
        authenticated_user = get_user_by_username(username)
        return authenticated_user['Item']
    except Exception as e:
        return None
