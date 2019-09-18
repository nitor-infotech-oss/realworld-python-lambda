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
    print(f"IN CREATE USEREVENT: {event}")
    print(f"LOAD :{json.dumps(event)}")
    json_data = json.loads(event['body'])
    print(json_data)
    print(type(json_data))
    data = json_data['user']
    print(data)
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
    # encoded = jwt.encode({'token': data['username']}, 'secret', algorithm='HS256')
    item = {
        # 'id': uuid.uuid4(),
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
        'token': min_token(data['username']),
        # 'token': token,
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
    res = {
        "user": body
    }
    return envelop(res)


def min_token(a_username):
    print(f"MIN TOKEN")
    expire = datetime.now() + timedelta(minutes=5)
    expire = calendar.timegm(expire.timetuple())
    payload = {
        'username': a_username,
        # 'expiresIn': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        # 'expiresIn': expire
    }
    print(f"PAYLOAD:{payload}")
    jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
    print(f"JWTTOKEN:{jwt_token}")
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
    print(f"RESP:{response}")
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
    print(f"EMAIL:{response}")
    return response


# login user
def login_user(event, context):
    print(f"LOGIN USER EVENT:{event}")
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
        raise Exception(f"Email not fount: {data['user']['email']}.", 422)

    if get_user_with_this_email['Items'][0]['password'] != data['user']['password']:
        raise Exception("Wrong password.", 422)

    token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbiI6ImdhdXRhbSJ9.5CLsX4nOuTagsC6nSGWfq-4oZZAL0RhlMLOm7QMGy_Q'

    authenticated_user = {
        'email': data['user']['email'],
        'token': min_token(get_user_with_this_email['Items'][0]['username']),
        # 'token': token,
        'username': get_user_with_this_email['Items'][0]['username']
        # 'bio': get_user_with_this_email['Items'][0]['bio'] if get_user_with_this_email['Items'][0]['bio'] else '',
        # 'image': get_user_with_this_email['Items'][0]['image'] if get_user_with_this_email['Items'][0]['image'] else ''
    }

    res = {
        'user': authenticated_user
    }
    return envelop(res)


# get user
def get_user(event, context):
    print(f"GET USER EVENT: {event}")
    authenticated_user = authenticate_and_get_user(event, context)
    print(authenticated_user)
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

    # response = {
    #     "statusCode": 200,
    #     "headers": {
    #         'Access-Control-Allow-Origin': 'http://localhost:4100',
    #         'Access-Control-Allow-Credentials': 'true'
    #     },
    #     "user": user
    # }
    res = {
        "user": user
    }
    return envelop(res)


def update_user(event, context):
    print(f"UPDATE USER EVENT: {event}")
    authenticated_user = authenticate_and_get_user(event, context)
    print(authenticated_user)
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    json_user = json.loads(event['body'])
    print(f"DATA: {json_user}")
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

    print(f"UPDATE: {updated_user}")

    table = dynamodb.Table('dev-user')
    table.put_item(Item=updated_user)
    print(f"AFTER UPDATE USER: {updated_user}")
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

    # response = {
    #     "statusCode": 200,
    #     "headers": {
    #         'Access-Control-Allow-Origin': 'http://localhost:4100',
    #         'Access-Control-Allow-Credentials': 'true'
    #     },
    #     "body": updated_user
    # }
    res = {
        "user": updated_user
    }
    return envelop(res)


def get_profile(event, context):
    print(f"GET PROFILE EVENT : {event}")
    username = event['pathParameters']['username']
    print(username)
    authenticated_user = authenticate_and_get_user(event, context)
    print(f"AUTH---:{authenticated_user}")
    profile = get_profile_by_username(username, authenticated_user)
    print(f"PROFILE: {profile}")
    if not profile:
        raise Exception(f"User not found: ${username}", 422)

    response = {
        "profile": profile
    }
    return response


def follow(event, context):
    print(f"FOLLOW EVENT: {event}")
    authenticated_user = authenticate_and_get_user(event, context)
    print(f"follow auth:{authenticated_user}")
    if not authenticated_user:
        raise Exception('Token not present or invalid.', 422)
    username = event['pathParameters']['username']
    user = get_user_by_username(username)['Item']
    print("*"*10,user)
    should_follow = (not event['httpMethod'] == 'DELETE')

    # Update "followers" field on followed user
    if should_follow:
        print("IN IF BLOCK")
        if user['followers'] and authenticated_user['username'] not in user['followers']:
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

    table = dynamodb.Table('dev-user')
    table.put_item(Item=user)

    # Update "following" field on follower user
    if should_follow:
        if authenticated_user['following'] and username not in authenticated_user['following']:
            authenticated_user['following'].append(username)
        else:
            authenticated_user['following'] = [username]
    else:
        if authenticated_user['following'] and username not in authenticated_user['following']:
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

    # response = {
    #     "statusCode": 200,
    #     "headers": {
    #         'Access-Control-Allow-Origin': '*',
    #         'Access-Control-Allow-Credentials': 'true'
    #     },
    #     "profile": profile
    # }
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
    print(f"get_followed_users : {user}")
    if 'following' in user:
        user['following'] = user['following']
    else:
        user['following'] = []
    return user['following']


def get_token_from_event(event, context):
    print(f"IN GET TOKEN EVENT:{event}")
    # return event.headers.Authorization.replace('Token ', '')
    return event['headers']['Authorization'].replace('Token ', '')


def get_profile_by_username(a_username, a_authenticated_user):
    user = get_user_by_username(a_username)['Item']
    print(f"PROFILE__USER**: {user}")
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

    # If user is authenticated, set following bit // user['followers']
    if 'followers' in user and a_authenticated_user:
        profile['following'] = a_authenticated_user['username'] in user['followers']

    return profile


def authenticate_and_get_user(event, context):
    print(f"AUTH&GETUSER EVENT: {event}")
    # if 'username' in event:
    #     username = event['username']
    # else:
    #     username = 'gp' # event['pathParameters']['username']
    try:
        token = get_token_from_event(event, context)
        print(f"TOKEN IN AUTH:{token}")
        decoded = jwt.decode(token, JWT_SECRET, JWT_ALGORITHM)# verify=False
        print(f"DECODE: {decoded}")
        username = decoded['username']
        print(f"USERNAME:{username}")
        authenticated_user = get_user_by_username(username)
        return authenticated_user['Item']
    except Exception as e:
        print(f"EXCEPTION :{e}")
        return None

# THESE METHODS ARE FOR TESTING PURPOSE START
def get_enough_article_query(filter_exp ,eav, queryParams):
    # print(queryParams)
    print(f"FILTER EXP: {filter_exp}")
    # print(f"IN USER: {eav}")
    # fe = author IN('gp')
    table = dynamodb.Table('dev-articles')


    response = table.query(
        IndexName='updatedAt',
        KeyConditionExpression='dummy= :dummy',
        # KeyConditionExpression=Key('dummy').eq('OK') & Key('author').eq('gp'),
        FilterExpression='author IN'+filter_exp,
        ExpressionAttributeValues=eav,
        ScanIndexForward=False,
    )
    print(f"get_enough_article_query:{response}")
    return response


def enough_articles(query_params='', authenticated_user='gp', limit=5, offset=0):
    print("IN START OF FUNC", limit, offset)
    ## START
    query_result_item = []
    table = dynamodb.Table('dev-article')
    while len(query_result_item) < (offset + limit):
        query_result = table.query(
            IndexName='updatedAt',
            KeyConditionExpression='dummy = :dummy',
            ExpressionAttributeValues={
                ':dummy': 'OK',
            },
            ScanIndexForward=False,
        )

        query_result_item.append(query_result['Items'])
    print(query_result_item)
    ## END


    # Call query repeatedly, until we have enough records, or there are no more
    # query_result_items = []
    # while len(query_result_items) < (offset + limit):
    #     query_result = ''
    #     # queryResult = Util.DocumentClient.query(queryParams)
    #
    #     query_result_items.append(query_result['Items'])
    #     if query_result['LastEvaluatedKey']:
    #         query_params.ExclusiveStartKey = query_result['LastEvaluatedKey']
    #     else:
    #         break
    #
    # # Decorate last "limit" number of articles with author data
    # article_promises = []
    # # query_result_items.slice(offset, offset + limit).forEach(a= >
    # # article_promises.append(transform_retrieved_article(a, authenticated_user)))
    # # articles = Promise.all(article_promises)
    # return articles


# THESE METHODS ARE FOR TESTING PURPOSE END