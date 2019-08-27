import logging
import uuid
import time
import boto3
from src import user
from datetime import datetime
from slugify import slugify

dynamodb = boto3.resource('dynamodb')


def create_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    data = event['body']

    if not data['article']:
        logging.error("Validation Failed")
        raise Exception("Article must be specified", 422)

    article_data = data['article']
    event_body = ['title', 'description', 'article_body']

    for fields in event_body:
        if fields not in article_data:
            logging.error("Validation Failed")
            raise Exception(f"{fields} must be specified", 422)

    timestamp = str(datetime.utcnow().timestamp())
    slug = slugify(article_data['title'] + '-' + '01')

    article = {
        'slug': slug,
        'title': article_data['title'],
        'description': article_data['description'],
        'body': article_data['body'],
        'createdAt': timestamp,
        'updatedAt': timestamp,
        'author': authenticated_user['username'],
        'dummy': 'OK'
    }

    if article_data['tagList']:
        article['tagList'] = list(article_data['tagList'])

    article_table = dynamodb.Table('dev-articles')
    article_table.put_item(Item=article)

    del article['dummy']
    article['tagList'] = article_data['tagList'] or []
    article['favorited'] = False
    article['favoritesCount'] = 0
    article['author'] = {
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
        "article": article
    }
    return response


def get_article(event, context):
    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)

    article_table = dynamodb.Table('dev-article')
    article = article_table.get_item(
        Key={
            'slug':slug
        }
    )['Item']

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)

    authenticated_user = user.authenticate_and_get_user(event, context)

    return {'article':transform_retrieved_article(article, authenticated_user)}


def update_article(event, context):
    pass
    data = event['body']
    article_mutation = data['article']
    if not article_mutation:
        logging.error("Validation Failed")
        raise Exception("Article mutation must be specified.", 422)

    # Ensure at least one mutation requested
    if not article_mutation['title'] and not article_mutation['description'] and not article_mutation['body']:
        logging.error("Validation Failed")
        raise Exception("At least one field must be specified: [title, description, article].", 422)
        # return "At least one field must be specified: [title, description, article].", 422

    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        return 'Must be logged in.', 422

    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)
        # return 'Slug must be specified.', 422
    article_table = dynamodb.Table('dev-articles')
    article = article_table.get_item(
        Key= {
            'slug':slug
        },
    )['Item']

    if not  article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)
        # return f"Article not found: {slug}", 422

    # Ensure article is authored by authenticated_user
    if article['author'] != authenticated_user['username']:
        logging.error("Validation Failed")
        raise Exception(f"Article can only be updated by author: {article['author']}", 422)
        # return f"Article can only be updated by author:  [{article['author']}]", 422
    ######### Need to check ##########
    for field in ['title', 'description', 'body']:
        if article_mutation[field]:
            article[field] = article_mutation[field]
    ######### Need to check ##########

    article_table.put_item(Item=article)

    updated_article = article_table.get_item(
        Key= {
            'slug':slug
        }
    )['Item']

    return {'article': transform_retrieved_article(updated_article, authenticated_user)}


def delete_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)
    article_table = dynamodb.Table('dev-articles')
    article = article_table.get_item(
        Key= {
            'slug':slug
        }
    )['Item']

    if not  article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)
        # return f"Article not found: {slug}", 422

    if article['author'] != authenticated_user['username']:
        raise Exception(f"Article can only be deleted by author: {article['author']}", 422)
        # return f"Article can only be deleted by author:  [{article['author']}]", 422

    data = article_table.delete_item(
        Key={
            'slug': slug
        }
    )

    response = {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "article": data
    }
    return response


def favorite_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)

    article_table = dynamodb.Table('dev-articles')
    article = article_table.get_item(
        Key={
            'slug':slug
        }
    )['Item']

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)
        # return f"Article not found: {slug}", 422

    should_favorite = (not event['httpMethod'] == 'DELETE')

    if should_favorite:
        if not article['favoritedBy']:
            article['favoritedBy'] = []
        article['favoritedBy'].append(authenticated_user['username'])
        article['favoritesCount'] = 1
    else:
        favorite_result = filter(lambda x: x !=authenticated_user['username'], article['favoritedBy'])
        article['favoritedBy'] = list(favorite_result)

        if len(article['favoritedBy']) == 0:
            del article['favoritedBy']

    article['favoritesCount'] = article['favoritedBy'] if article['favoritedBy'] else len(article['favoritedBy']) == 0 # Need to Check

    article_table.put(Item=article)
    article = transform_retrieved_article(article)
    article['favorited'] = should_favorite

    return {
        "statusCode": 200,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        'article':article
    }


def list_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    params = event['queryStringParameters'] or {}
    limit = int(params['limit']) or 20
    offset = int(params['offset']) or 0
    articles_table = dynamodb.Table('dev-articles')
    if (params['tag'] and params['author']) or (params['author'] and params['favorited']) or (params['favorited'] and params['tag']):
        logging.error("Validation Failed")
        raise Exception("Only one of these can be specified: [tag, author, favorited]", 422)
    query_params = {
        'TableName': articles_table,
        'IndexName':'updatedAt',
        'KeyConditionExpression': 'dummy = :dummy',
        'ExpressionAttributeValues' :{
                                        ':dummy': 'OK',
                                    },
        'ScanIndexForward': False
    }
    ######### Need to check ##########
    if params['tag']:
        query_params['FilterExpression'] = 'contains(tagList, :tag)'
        query_params["ExpressionAttributeValues[':tag']"] = params['tag']
    elif params['author']:
        query_params['FilterExpression'] = 'author = :author'
        query_params.ExpressionAttributeValues[':author'] = params['author']
    elif params['favorited']:
        query_params['FilterExpression'] = 'contains(favoritedBy, :favorited)'
        query_params["ExpressionAttributeValues[':favorited']"] = params['favorited']
    ######### Need to check ##########

    return {
        'articles':query_enough_articles(query_params, authenticated_user,limit, offset)
    }

                        
def get_feed(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    params = event['queryStringParameters'] or {}
    limit = int(params['limit']) or 20
    offset = int(params['offset']) or 0

    followed = user.get_followed_users(authenticated_user['username'])
    if not len(followed):
        return {'articles': []}

    query_params = {
        'IndexName':'updatedAt',
        'KeyConditionExpression': 'dummy = :dummy',
        'FilterExpression': 'author IN ',
        'ExpressionAttributeValues': {
            ':dummy': 'OK',
        },
        'ScanIndexForward': False,
    }

    for i in range(0, len(followed)):
        query_params['ExpressionAttributeValues'][f":author{i}"] = followed[i]
    # ExpressionAttributeValues
    eav = query_params['ExpressionAttributeValues']

    list_query_params = filter(lambda x: x != ':dummy', query_params['ExpressionAttributeValues'].keys())

    # list_queryParams = map(lambda x:x.replace("'",""), list_query_params)
    list_query_params = tuple(list_query_params)
    # fe = "author IN{}".format(list_queryParams)
    # FilterExpression
    fe = str(list_query_params).replace("'", "")

    articles = get_enough_article_query_tags(eav, fe, authenticated_user, offset, limit)

    return {'articles': articles}


def get_tags(event,context):
    unique_tags = {}
    last_evaluated_key = None
    pe = 'tagList'
    articles_table = dynamodb.Table('dev-articles')
    if last_evaluated_key:
        response = articles_table.scan(
            ProjectionExpression=pe,
            ExclusiveStartKey=last_evaluated_key
        )
    else:
        response = articles_table.scan(
            ProjectionExpression=pe,
        )

    for item in response['Items']:
        if item['email'] and item['email'].values():
            for i in item['email'].values():
                unique_tags[i] = 1
                # print(f"TAG: {i} UTAG: {unique_tags}")
    last_evaluated_key = response['LastEvaluatedKey']

    while last_evaluated_key in response:
        tags = unique_tags.keys()
        # response = articles_table.scan(
        #     ProjectionExpression=pe,
        #     # FilterExpression=fe,
        #     # ExpressionAttributeNames=ean,
        #     ExclusiveStartKey=response['LastEvaluatedKey']
        # )
        #
        # for i in response['Items']:
        #     print(i)
    return {'tags': tags}


def query_enough_articles(query_params, authenticated_user,limit, offset):
    # Call query repeatedly, until we have enough records, or there are no more
    query_result_items = []
    while len(query_result_items) < (offset + limit):
        query_result = ''
        # queryResult = Util.DocumentClient.query(queryParams)

        query_result_items.append(query_result['Items'])
        if query_result['LastEvaluatedKey']:
            query_params.ExclusiveStartKey = query_result['LastEvaluatedKey']
        else:
            break

    # Decorate last "limit" number of articles with author data
    article_promises = []
    # query_result_items.slice(offset, offset + limit).forEach(a= >
    # article_promises.append(transform_retrieved_article(a, authenticated_user)))
    # articles = Promise.all(article_promises)
    return articles


def get_enough_article_query_tags(eav, fe, authenticated_user, offset, limit):
    # print(f"FILTER EXP: {filter_exp}")
    query_result_item = []
    table = dynamodb.Table('dev-articles')
    while len(query_result_item) < (offset + limit):
        query_result = table.query(
            IndexName='updatedAt',
            KeyConditionExpression='dummy= :dummy',
            FilterExpression='author IN'+fe,
            ExpressionAttributeValues=eav,
            ScanIndexForward=False,
        )
        query_result_item.append(query_result['Items'])
        if query_result['LastEvaluatedKey']:
            # filter_exp.ExclusiveStartKey = query_result.LastEvaluatedKey
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy= :dummy',
                FilterExpression='author IN' + fe,
                ExpressionAttributeValues=eav,
                ScanIndexForward=False,
                ExclusiveStartKey=query_result['LastEvaluatedKey']
            )
        else:
            break
        print(f"get_enough_article_query:{query_result}")

    article_data_list = []
    res = query_result_item[offset:(offset + limit)]
    for data in res:
        article_data_list.append(transform_retrieved_article(data, authenticated_user))
    articles = article_data_list
    return {'articles': articles}                        
  
                        
def transform_retrieved_article(article, authenticated_user):
    del article['dummy']
    article['tagList'] = article['tagList'] if article['tagList'] else article['tagList'] = []
    article['favoritesCount'] = article['favoritesCount'] or 0
    article['favorited'] = False

    if article['favoritedBy'] and authenticated_user:
        article['favorited'] = article['favoritedBy'] in authenticated_user['username']

    del article['favoritedBy']
    article['author'] = user.get_profile_by_username(article['author'],authenticated_user)

    return article
