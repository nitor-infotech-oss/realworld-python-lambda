import json
import boto3
import logging
import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
from src import user
from src.util import envelop

dynamodb = boto3.resource('dynamodb')


def create(event, context):
    print(f"IN CREATE COMMENT EVENT: {event}")
    authenticated_user = user.authenticate_and_get_user(event, context)
    print(authenticated_user)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    data = json.loads(event['body'])
    print("++++++++++++++++++++++++++++++",type(data))
    print(f"comment data: {data}")
    if not data['comment']:
        logging.error("Validation Failed")
        raise Exception("Comment must be specified", 422)

    table = dynamodb.Table('dev-article')
    comment_body = data['comment']['body']
    print("*****************************",type(comment_body))
    print(f"comment_body data: {comment_body}")
    slug = event['pathParameters']['slug']
    article = table.get_item(
        Key={
            'slug': slug
        }
    )['Item']
    print(article)

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)

    timestamp = str(datetime.utcnow().timestamp())
    comment = {
        'id': str(uuid.uuid1()),
        'slug': slug,
        'body': comment_body,
        'created_at': timestamp,
        'updated_at': timestamp,
        'author': authenticated_user['username']
    }

    comment_table = dynamodb.Table('dev-comments')
    comment_table.put_item(Item=comment)

    if 'bio' in authenticated_user:
        authenticated_user['bio'] = user['bio']
    else:
        authenticated_user['bio'] = ''
    if 'image' in authenticated_user:
        authenticated_user['image'] = authenticated_user['image']
    else:
        authenticated_user['image'] = ''

    comment['author'] = {
        'username': authenticated_user['username'],
        'bio': authenticated_user['bio'],
        'image': authenticated_user['image'],
        'following': False
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': 'http://localhost:4100',
            'Access-Control-Allow-Credentials': True
        },
        "comment": comment
    }
    res = {
        "comment": comment
    }
    print(f"create comment res :{res}")
    return envelop(res)


def get(event, context):
    print(f"GET COMMENT EVENT: {event}")
    authenticated_user = user.authenticate_and_get_user(event, context)
    slug = event['pathParameters']['slug']

    table = dynamodb.Table('dev-comments')
    comments = table.query(
        IndexName='article',
        KeyConditionExpression='slug= :slug',
        ExpressionAttributeValues={
            ':slug': slug,
        },
    )['Items']

    for i in range(len(comments)):
        comments[i]['author'] = user.get_profile_by_username(comments[i]['author'], authenticated_user)
    res = {
        'comments':comments
    }
    # response = {
    #     "statusCode": 200,
    #     "headers": {
    #         'Access-Control-Allow-Origin': 'http://localhost:4100',
    #         'Access-Control-Allow-Credentials': 'true'
    #     },
    #     "body": json.dumps(res)
    # }
    return envelop(res)


def delete(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context);
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception('Must be logged in.', 422)

    comment_id = event['pathParameters']['id']
    comment_table = dynamodb.Table('dev-comments')
    comment = comment_table.get_item(
        Key={
            'id': comment_id
        },
    )['Item']

    if not comment:
        raise Exception(f"Comment ID not found: {comment_id}", 422)

    # Only comment author can delete comment
    if not comment['author'] == authenticated_user['username']:
        raise Exception(f"Only comment author can delete: {comment['author']}", 422)

    comment_table = dynamodb.Table('dev-comments')
    data = comment_table.delete_item(
        Key={
            'id': comment_id
        }
    )
    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "comments": data
    }
    res = {
        "comments": data
    }
    return envelop(res)

