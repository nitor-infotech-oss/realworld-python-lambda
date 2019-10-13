import os
import json
import logging
import uuid
import time
import boto3
from boto3.dynamodb.conditions import Key, Attr
# import bcrypt
import jwt
from src.util import envelop
from datetime import datetime, timedelta
import calendar

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')

JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 172800  # 2 days


# create user
def create_user(event, context):
    json_data = json.loads(event['body'])
    data = json_data['user']
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

    table = dynamodb.Table('dev-user')

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
    item = {
        'username': data['username'],
        'email': data['email'],
        'password': data['password'],
        'createdAt': timestamp,
        'updatedAt': timestamp
    }

    # create the user to the database
    table.put_item(Item=item)
    body = {
        'email': data['email'],
        'token': min_token(data['username']),
        'username': data['username'],
        'bio': '',
        'image': ''
    }
    # create a response
    res = {
        "user": body
    }
    return envelop(res)


def min_token(a_username):
    expire = datetime.now() + timedelta(minutes=60)
    expire = calendar.timegm(expire.timetuple())
    payload = {
        'username': a_username,
        # 'expiresIn': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        'expiresIn': expire
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    return str(jwt_token, 'UTF8')


def get_user_by_username(username):
    table = dynamodb.Table('dev-user')
    print(username)
    try:
        response = table.get_item(
            Key={
                'username': username
            }
        )
    except Exception as e:
        response = None
    return response


def get_user_by_email(a_email):
    table = dynamodb.Table('dev-user')
    response = table.query(
        IndexName='email',
        KeyConditionExpression='email= :email',
        ExpressionAttributeValues={
            ':email': a_email,
        },
        Select='ALL_ATTRIBUTES',
    )
    return response


# login user
def login_user(event, context):
    load_data = json.loads(event['body'])
    data = load_data
    if not data:
        logging.error("Validation Failed")
        raise Exception("User must be specified.", 422)
    if 'email' not in data['user']:
        logging.error("Validation Failed")
        raise Exception("Email must be specified.", 422)
    if 'password' not in data['user']:
        logging.error("Validation Failed")
        raise Exception("Password must be specified.", 422)

    # Get user with this email
    get_user_with_this_email = get_user_by_email(data['user']['email'])
    if get_user_with_this_email['Count'] != 1:
        logging.error("Validation Failed")
        # raise Exception(f"Email not fount: {data['user']['email']}.", 422)
        return envelop(f"Email not fount: {data['user']['email']}.",422)

    if get_user_with_this_email['Items'][0]['password'] != data['user']['password']:
        # raise Exception("Wrong password.", 422)
        return envelop(f"Wrong password.", 422)

    if 'bio' in get_user_with_this_email['Items'][0]:
        bio_content = get_user_with_this_email['Items'][0]['bio']
    else:
        bio_content = ''
    if 'image' in get_user_with_this_email['Items'][0]:
        image_url = get_user_with_this_email['Items'][0]['image']
    else:
        image_url = ''

    authenticated_user = {
        'email': data['user']['email'],
        'token': min_token(get_user_with_this_email['Items'][0]['username']),
        'username': get_user_with_this_email['Items'][0]['username'],
        'bio': bio_content,
        'image': image_url
    }

    res = {
        'user': authenticated_user
    }
    return envelop(res)


# get user
def get_user(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    if 'bio' in authenticated_user:
        authenticated_user['bio'] = authenticated_user['bio']
    else:
        authenticated_user['bio'] = ''
    if 'image' in authenticated_user:
        authenticated_user['image'] = authenticated_user['image']
    else:
        authenticated_user['image'] = ''
    user = {
        'email': authenticated_user['email'],
        'token': get_token_from_event(event, context),
        'username': authenticated_user['username'],
        'bio': authenticated_user['bio'],
        'image':  authenticated_user['image'],
    }

    res = {
        "user": user
    }
    return envelop(res)


def update_user(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    json_user = json.loads(event['body'])
    user = json_user['user']
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
            raise Exception(f"Email already taken: {user['email']}", 422)

        updated_user['email'] = user['email']

    if 'password' in user:
        # updatedUser.password = bcrypt.hashSync(user.password, 5);
        updated_user['password'] = user['password']

    if user['image']:
        updated_user['image'] = user['image']

    if user['bio']:
        updated_user['bio'] = user['bio']

    table = dynamodb.Table('dev-user')
    table.put_item(Item=updated_user)
    if updated_user['password']:
        del updated_user['password']

    if not updated_user['email']:
        updated_user['email'] = authenticated_user['email']

    if 'image' not in updated_user:
        if 'image' in authenticated_user:
            updated_user['image'] = authenticated_user['image']
        else:
            updated_user['image'] = ''
    else:
        updated_user['image'] = updated_user['image']

    if 'bio' not in updated_user:
        if 'bio' in authenticated_user:
            updated_user['bio'] = authenticated_user['bio']
        else:
            updated_user['bio'] = ''
    else:
        updated_user['bio'] = updated_user['bio']

    updated_user['token'] = get_token_from_event(event, context)

    res = {
        "user": updated_user
    }
    return envelop(res)


def get_profile(event, context):
    username = event['pathParameters']['username']
    authenticated_user = authenticate_and_get_user(event, context)
    profile = get_profile_by_username(username, authenticated_user)
    if not profile:
        raise Exception(f"User not found: ${username}", 422)

    response = {
        "profile": profile
    }

    return envelop(response)


def follow(event, context):
    authenticated_user = authenticate_and_get_user(event, context)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    username = event['pathParameters']['username']
    user = get_user_by_username(username)['Item']
    should_follow = (not event['httpMethod'] == 'DELETE')

    # Update "followers" field on followed user
    if should_follow:
        if 'followers' in user and authenticated_user['username'] not in user['followers']:
            user['followers'].append(authenticated_user['username'])
        else:
            user['followers'] = [authenticated_user['username']]
    else:
        if 'followers' in user and authenticated_user['username'] in user['followers']:
            # create new list of follower except authenticated user
            follow_result = filter(lambda x: x != authenticated_user['username'], user['followers'])
            user['followers'] = list(follow_result)

            # delete followers if list is empty
            if not len(user['followers']):
                del user['followers']

    table = dynamodb.Table('dev-user')
    table.put_item(Item=user)

    # Update "following" field on follower user
    if should_follow:
        if 'following' in authenticated_user and username not in authenticated_user['following']:
            authenticated_user['following'].append(username)
        else:
            authenticated_user['following'] = [username]
    else:
        if 'following' in authenticated_user and username not in authenticated_user['following']:
            # create new list of following except username
            result = filter(lambda x: x != username, authenticated_user['following'])
            authenticated_user['following'] = list(result)

            # delete following if list is empty
            if not len(authenticated_user['following']):
                del authenticated_user['following']

    table.put_item(Item=authenticated_user)
    if 'bio' in user:
        user['bio'] = user['bio']
    else:
        user['bio'] = ''
    if 'image' in user:
        user['image'] = user['image']
    else:
        user['image'] = ''

    profile = {
        'username': username,
        'bio': user['bio'],
        'image': user['image'],
        'following': should_follow
    }

    res = {
        "profile": profile
    }
    return envelop(res)


# create followed users
def get_followed_users(a_username):
    table = dynamodb.Table('dev-user')
    user = table.get_item(
        Key={
            'username': a_username
        }
    )['Item']
    if 'following' in user:
        user['following'] = user['following']
    else:
        user['following'] = []
    return user['following']


def get_token_from_event(event, context):
    return event['headers']['Authorization'].replace('Token ', '')


def get_profile_by_username(a_username, a_authenticated_user):
    user = get_user_by_username(a_username)['Item']
    if not user:
        return None
    if 'bio' in user:
        user['bio'] = user['bio']
    else:
        user['bio'] = ''
    if 'image' in user:
        user['image'] = user['image']
    else:
        user['image'] = ''

    profile = {
        'username': user['username'],
        'bio': user['bio'],
        'image': user['image'],
        'following': False,
    }

    # If user is authenticated, set following bit
    if 'followers' in user and a_authenticated_user:
        profile['following'] = a_authenticated_user['username'] in user['followers']

    return profile


def authenticate_and_get_user(event, context):
    print(f"AUTH&GETUSER EVENT: {event}")
    try:
        token = get_token_from_event(event, context)
        decoded = jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)# verify=False
        username = decoded['username']
        authenticated_user = get_user_by_username(username)
        return authenticated_user['Item']
    except Exception as e:
        print(f"EXCEPTION :{e}")
        return None

