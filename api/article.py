import json
import boto3
import logging
import uuid
from datetime import datetime
from slugify import slugify
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb')


def create_article(event, context):
    # data = event['body']
    event_body = ['title', 'description', 'article_body']

    if not event:
        logging.error("Validation Failed")
        raise Exception("Article must be specified", 422)

    for fields in event_body:
        if fields not in event:
            logging.error("Validation Failed")
            raise Exception(f"{fields} must be specified", 422)

    timestamp = str(datetime.utcnow().timestamp())
    slug = slugify(event['title'])
    table = dynamodb.Table('articles')

    item = {
        'slug': slug,
        # 'article_id': str(uuid.uuid1()),
        'title': event['title'],
        'description': event['description'],
        'article_body': event['article_body'],
        # TODO will take user_id and author from session
        'user_id': event['user_id'],
        'author': event['author'],
        'createdAt': timestamp,
        'updatedAt': timestamp,
        'dummy': 'OK'
    }

    table.put_item(Item=item)

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": json.dumps(item)
    }
    return response


def get_article(event, context):
    table = dynamodb.Table('articles')
    result = table.scan()

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": json.dumps(result['Items'])
    }

    return response


def update_article(event, context):

    if not event:
        logging.error("Validation Failed")
        raise Exception("Article must be specified", 422)

    if 'title' and 'description' and 'article_body' not in event:
        raise Exception("At least one field must be specified: [title, description, article_body].", 422)
    if 'slug' not in event:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified", 422)

    timestamp = str(datetime.utcnow().timestamp())

    table = dynamodb.Table('articles')
    result = table.update_item(
        Key={
            'slug': event['pathParameters']['slug']
        },
        ExpressionAttributeNames={
            '#title': 'title',
            '#description': 'description',
            '#article_body': 'article_body'
        },
        ExpressionAttributeValues={
            ':title': event['title'],
            ':description': event['description'],
            ':article_body': event['article_body'],
            ':updatedAt': timestamp,
        },
        UpdateExpression='SET #title = :title, '
                         '#description = :description, '
                         '#article_body = :article_body, '
                         'updatedAt = :updatedAt',
        ReturnValues='ALL_NEW',
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": json.dumps(result['Attributes'])
    }

    return response


def delete_article(event, context):
    if not event:
        logging.error("Validation Failed")
        raise Exception("Article must be specified", 422)

    if 'slug' not in event:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified", 422)

    table = dynamodb.Table('articles')
    result = table.get_item(
        Key={
            'slug': event['slug']
        }
    )
    if not result['Items']:
        raise Exception(f"Article not found: {event['slug']}", 422)

    result = table.delete_item(
        Key={
            'slug': event['slug']

        }
    )
    if result:
        message = {"msg": "Article deleted successfully ", "data": result['Items']}
    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": json.dumps(message)
    }
    return response
