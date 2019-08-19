import logging
import uuid
import time
import boto3
from boto3.dynamodb.conditions import Key, Attr
# import bcrypt
# import jwt
from src.util import envelop
from datetime import datetime, timedelta

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 172800  # 2 days


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
    item = {
        # 'id': str(uuid.uuid1()),
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
        'email': data['email'],
        # 'token': min_token(data['username']),
        'token': token,
        'username': data['username'],
        'bio': '',
        'image': ''
    }
    # create a response
    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "user": body
    }

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
        'email': data['email'],
        # 'token': min_token(get_user_with_this_email['Items'][0]['username']),
        'token': token,
        'username': get_user_with_this_email['Items'][0]['username']
        # 'bio': get_user_with_this_email['Items'][0]['bio'] if get_user_with_this_email['Items'][0]['bio'] else '',
        # 'image': get_user_with_this_email['Items'][0]['image'] if get_user_with_this_email['Items'][0]['image'] else ''
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "user": authenticated_user
    }
    return response


# get user
def get_user(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)

    body = {
        'email': authenticated_user['email'],
        # 'token': get_token_from_event(event, context),
        'username': authenticated_user['username']
        # 'bio': authenticated_user['bio'] if authenticated_user['bio'] else '',
        # 'image':  authenticated_user['image'] if authenticated_user['image'] else ''
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "user": body
    }
    return response


def update_user(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    user = event
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


authenticate_and_get_user(event, context)
get_user_by_username(username)


def get_profile(event, context):
    username = event['pathParameters']['username']
    authenticated_user = authenticate_and_get_user(event, context)
    profile = get_profile_by_username(username, authenticated_user);
    print(f"PROFILE: {profile}")
    if not profile:
        raise Exception(f"User not found: ${username}", 422)

    response = {
        "profile": profile
    }
    return response


get_profile_by_username(a_username, a_authenticated_user)


def follow(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    username = event['pathParameters']['username']
    user = (get_user_by_username(username))['Item']
    should_follow = (not event['httpMethod'] == 'DELETE')

    # Update "followers" field on followed user
    if should_follow:
        if user['followers'] and authenticated_user['username'] not in user['followers']:
            pass
            user['followers'].append(authenticated_user['username'])
        else:
            user['followers'] = [authenticated_user['username']]
    else:
        if user['followers'] and authenticated_user['username'] in user['followers']:
            # create new list of follower except authenticated user
            follow_result = filter(lambda x: x != authenticated_user['username'], user['followers'])
            user['followers'] = list(follow_result)

            # delete followers if list is empty
            if not len(user['followers']):
                print("In Delete condition")
                del user['followers']

    table = dynamodb.Table('dev-users')
    table.put_item(Item=user)

    # Update "following" field on follower user
    if should_follow:
        if authenticated_user['following'] and username not in authenticated_user['following']:
            authenticated_user['following'].append(username)
        else:
            authenticated_user['following'] = [username]
    else:
        if authenticated_user['following'] and username in authenticated_user['following']:
            # create new list of following except username
            result = filter(lambda x: x != username, authenticated_user['following'])
            authenticated_user['following'] = list(result)

            # delete following if list is empty
            if not len(authenticated_user['following']):
                del authenticated_user['following']

    table.put_item(Item=authenticated_user)

    profile = {
        'username': username,
        'bio': user['bio'] if user['bio'] else '',
        'image': user['image'] if user['bio'] else '',
        'following': should_follow
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "profile": profile
    }

    return response


# create followed users
def get_followed_users(a_username):
    table = dynamodb.Table('dev-users')
    user = table.get_item(
        Key={
            'username': a_username
        }
    )['Item']

    return user['following'] or user['following']== []


def min_token(a_username):
    payload = {
        'username': a_username,
        'expiresIn': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return jwt_token


def get_user_by_email(a_email):
    table = dynamodb.Table('dev-users')
    response = table.query(
        IndexName='email',
        KeyConditionExpression='email= :email',
        ExpressionAttributeValues={
            ':email': a_email,
        },
        Select='ALL_ATTRIBUTES',
    )
    print(f"EMAIL:{response}")
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


def get_token_from_event(event, context):
    pass
    # return event.headers.Authorization.replace('Token ', '')
    return event['headers']['authorization'].replace('Token', '')


def get_profile_by_username(a_username, a_authenticated_user):
    user = get_user_by_username(a_username)['Item']
    print(f"PROFILE USER: {user}")
    if not user:
        return None

    profile = {
        'username': user['username']
        # 'bio': user['bio'] if user['bio'] else '',
        # 'image': user['image'] if user['image'] else '',
        # 'following': False,
    }

    # If user is authenticated, set following bit
    if user['followers'] and a_authenticated_user:
        profile['following'] = user['followers']in a_authenticated_user['username']

    return profile


def authenticate_and_get_user(event, context):
    if 'username' in event:
        username = event['username']
    else:
        username = event['pathParameters']['username']
    try:
        # token = get_token_from_event(event, context)
        # decoded = jwt.verify(token, Util.tokenSecret),
        username = username  # decoded.username,
        authenticated_user = get_user_by_username(username)
        return authenticated_user['Item']
    except Exception as e:
        return None
