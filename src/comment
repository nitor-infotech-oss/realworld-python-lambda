import boto3
import logging
import uuid
from datetime import datetime
from src import user

dynamodb = boto3.resource('dynamodb')


def create(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)

    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    data = event['body']
    if not data['comment'] or not data['comment']['body']:
        logging.error("Validation Failed")
        raise Exception("Comment must be specified", 422)

    table = dynamodb.Table('dev-article')
    comment_body = data['comment']['body']
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
        'id': uuid.uuid4(),
        'slug': slug,
        'body': comment_body,
        'created_at': timestamp,
        'updated_at': timestamp,
        'author': authenticated_user['username']
    }

    comment_table = dynamodb.Table('dev-comments')
    comment_table.put_item(Item=comment)
    comment['author'] = {
        'username': authenticated_user['username'],
        'bio': authenticated_user['bio'] or '',
        'image': authenticated_user['image'] or '',
        'following': False
    }

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "comment": comment
    }

    return response


def get(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    slug = event['pathParameters']['slug']

    table = dynamodb.Table('dev-users')
    comments = table.query(
        IndexName='article',
        KeyConditionExpression='slug= :slug',
        ExpressionAttributeValues={
            ':slug': slug,
        },
    )['Items']

    for i in range(len(comments)):
        comments[i]['author'] = user.get_profile_by_username(comments[i]['author'], authenticated_user)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "comments": comments
    }
    return response


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
    return response

