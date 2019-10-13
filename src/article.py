import json
import logging
import uuid
import time
import boto3
from src import user
from src.util import envelop
from datetime import datetime
from slugify import slugify
import simplejson
from decimal import *
import random

dynamodb = boto3.resource('dynamodb', region_name='us-west-2')


def create_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    data = json.loads(event['body'])

    if not data['article']:
        logging.error("Validation Failed")
        raise Exception("Article must be specified", 422)

    article_data = data['article']
    event_body = ['title', 'description', 'body']

    for fields in event_body:
        if fields not in article_data:
            logging.error("Validation Failed")
            raise Exception(f"{fields} must be specified", 422)

    timestamp = Decimal(datetime.utcnow().timestamp())
    readable = time.ctime(timestamp)
    slug = slugify(article_data['title']+'-'+str(random.randrange(100000, 999999)))

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

    article_table = dynamodb.Table('dev-article')
    article_table.put_item(Item=article)

    del article['dummy']
    if 'tagList' in article_data:
        article['tagList'] = article_data['tagList']
    else:
        article['tagList'] = []

    article['favorited'] = False
    article['favoritesCount'] = 0

    if 'bio' in authenticated_user:
        authenticated_user['bio'] = authenticated_user['bio']
    else:
        authenticated_user['bio'] = ''
    if 'image' in authenticated_user:
        authenticated_user['image'] = authenticated_user['image']
    else:
        authenticated_user['image'] = ''

    article['author'] = {
        'username': authenticated_user['username'],
        'bio': authenticated_user['bio'],
        'image': authenticated_user['image'],
        'following': False
    }
    article['createdAt'] = readable
    article['updatedAt'] = readable

    res = {
        "article": article
    }
    return envelop(res)


def get_article(event, context):
    print(f"GET ARTICLE EVENT: {event}")
    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)

    article_table = dynamodb.Table('dev-article')
    article = article_table.get_item(
        Key={
            'slug': slug
        }
    )['Item']

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)

    authenticated_user = user.authenticate_and_get_user(event, context)
    res = {
        'article': transform_retrieved_article(article, authenticated_user)
    }

    dateup_res = simplejson.dumps(article['updatedAt'])
    article['updatedAt'] = time.ctime(float(dateup_res))
    article['createdAt'] = simplejson.dumps(article['createdAt'])
    article['createdAt'] = time.ctime(float(article['createdAt']))
    article['favoritesCount'] = int(simplejson.dumps(article['favoritesCount']))

    return envelop(res)


def update_article(event, context):
    print(f"UPDATE ARTICLE EVENT: {event}")
    data = json.loads(event['body'])
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
    article_table = dynamodb.Table('dev-article')
    article = article_table.get_item(
        Key= {
            'slug': slug
        },
    )['Item']

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)
        # return f"Article not found: {slug}", 422

    # Ensure article is authored by authenticated_user
    if article['author'] != authenticated_user['username']:
        logging.error("Validation Failed")
        raise Exception(f"Article can only be updated by author: {article['author']}", 422)

    for field in ['title', 'description', 'body']:
        if article_mutation[field]:
            print(f"article_mutation[field] : {field}")
            article[field] = article_mutation[field]
            print(f"TEST FIELD: {article[field]}")

    article_table.put_item(Item=article)

    updated_article = article_table.get_item(
        Key= {
            'slug': slug
        }
    )['Item']

    res = {
        'article': transform_retrieved_article(updated_article, authenticated_user)
    }

    dateup_res = simplejson.dumps(updated_article['updatedAt'])
    updated_article['updatedAt'] = time.ctime(float(dateup_res))
    updated_article['createdAt'] = simplejson.dumps(updated_article['createdAt'])
    updated_article['createdAt'] = time.ctime(float(updated_article['createdAt']))
    if 'favoritesCount' in updated_article:
        updated_article['favoritesCount'] = int(simplejson.dumps(updated_article['favoritesCount']))

    return envelop(res)


def delete_article(event, context):
    print(f"DELETE ARTICLE EVENT : {event}")
    authenticated_user = user.authenticate_and_get_user(event, context)

    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)
    article_table = dynamodb.Table('dev-article')
    article = article_table.get_item(
        Key={
            'slug': slug
        }
    )['Item']

    if not article:
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

    res = {
        "article": data
    }
    return envelop(res)


def favorite_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    slug = event['pathParameters']['slug']

    if not slug:
        logging.error("Validation Failed")
        raise Exception("Slug must be specified.", 422)

    article_table = dynamodb.Table('dev-article')
    article = article_table.get_item(
        Key={
            'slug': slug
        }
    )['Item']

    if not article:
        logging.error("Validation Failed")
        raise Exception(f"Article not found: {slug}", 422)
        # return f"Article not found: {slug}", 422

    should_favorite = (not event['httpMethod'] == 'DELETE')

    if should_favorite:
        if 'favoritedBy' not in article:
            article['favoritedBy'] = []
        article['favoritedBy'].append(authenticated_user['username'])
        article['favoritesCount'] = 1
    else:
        favorite_result = filter(lambda x: x !=authenticated_user['username'], article['favoritedBy'])
        article['favoritedBy'] = list(favorite_result)

        if len(article['favoritedBy']) == 0:
            del article['favoritedBy']
            # article['favoritedBy'] = []

    try:
        if 'favoritedBy' in article:
            article['favoritesCount'] = len(article['favoritedBy'])
        else:
            article['favoritesCount'] = 0

        article_table.put_item(Item=article)
        article = transform_retrieved_article(article, authenticated_user)
        article['favorited'] = should_favorite

    except Exception as e:
        print(f"Exception: {e}")

    res = {
        'article': article
    }

    dateup_res = simplejson.dumps(article['updatedAt'])
    article['updatedAt'] = time.ctime(float(dateup_res))
    article['createdAt'] = simplejson.dumps(article['createdAt'])
    article['createdAt'] = time.ctime(float(article['createdAt']))
    article['favoritesCount'] = int(simplejson.dumps(article['favoritesCount']))

    return envelop(res)


def list_article(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if 'queryStringParameters' in event:
        if event['queryStringParameters']:
            params = event['queryStringParameters']
        else:
            params = {}
        if params['limit']:
            limit = params['limit']
        else:
            limit = 20
        if params['offset']:
            offset = params['offset']
        else:
            offset = 0

    articles_table = dynamodb.Table('dev-article')

    try:
        if ('tag' and 'author' in params) or ('author' and 'favorited' in params) or ('favorited' and 'tag' in params):
            logging.error("Validation Failed")
            raise Exception("Only one of these can be specified: [tag, author, favorited]", 422)
    except Exception as e:
        print(f"Exception occurred in params: {e}")
    query_params = {
        'TableName': articles_table,
        'IndexName': 'updatedAt',
        'KeyConditionExpression': 'dummy = :dummy',
        'ExpressionAttributeValues': {
                                        ':dummy': 'OK',
                                    },
        'ScanIndexForward': False
    }

    try:
        flag = 0
        if 'tag' in params:
            query_params = params['tag']
            flag = 1
        elif 'author' in params:
            query_params = params['author']
            flag = 2
        elif 'favorited' in params:
            query_params = params['favorited']
            flag = 3
    except Exception as e:
        print(f"Exception occurred while listing article: {e}")

    articles = query_enough_articles(query_params, authenticated_user, limit, offset, flag)

    articles = simplejson.dumps(articles)

    temp = {
        'articles': json.loads(articles)
    }

    final = []
    for dates in temp['articles']:
        if 'updatedAt' and 'createdAt' in dates.keys():
            dates['updatedAt'] = time.ctime(dates['updatedAt'])
            dates['createdAt'] = time.ctime(dates['createdAt'])
        if 'favoriteCount' in dates.keys():
            dates['favoritesCount'] = int(simplejson.dumps(dates['favoritesCount']))

            final.append(dates)

    res = {
        'articles': final
    }

    return envelop(res)


def get_feed(event, context):
    authenticated_user = user.authenticate_and_get_user(event, context)
    if not authenticated_user:
        logging.error("Validation Failed")
        raise Exception("Must be logged in.", 422)

    params = event['queryStringParameters']
    if params['limit']:
        limit = int(params['limit'])
    else:
        limit = 20

    if params['offset']:
        offset = int(params['offset'])
    else:
        offset = 0

    followed = user.get_followed_users(authenticated_user['username'])

    if not len(followed):
        # print({'articles': []})
        return envelop({'articles': []})

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
    eav = query_params['ExpressionAttributeValues']

    list_query_params = filter(lambda x: x != ':dummy', query_params['ExpressionAttributeValues'].keys())

    # list_queryParams = map(lambda x:x.replace("'",""), list_query_params)
    list_query_params = tuple(list_query_params)

    if len(list_query_params) == 1:
        fe = str(list_query_params).replace("'", "")
        fe = fe.replace(",", "")
    else:
        fe = str(list_query_params).replace("'", "")

    articles = get_enough_article_query_tags(eav, fe, authenticated_user, offset, limit)

    articles = simplejson.dumps(articles)
    temp = json.loads(articles)

    final_data = []
    for dates in temp['articles']:
        if 'updatedAt' and 'createdAt' in dates.keys():
            dates['updatedAt'] = time.ctime(dates['updatedAt'])
            dates['createdAt'] = time.ctime(dates['createdAt'])

        if 'favoritesCount' in dates.keys():
            dates['favoritesCount'] = int(simplejson.dumps(dates['favoritesCount']))

            final_data.append(dates)

    res = {
        'articles': final_data
    }

    return envelop(res)


def get_tags(event,context):
    unique_tags = {}
    last_evaluated_key = None
    pe = 'tagList'
    articles_table = dynamodb.Table('dev-article')
    tags = ''
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
        if 'tagList' in item and item.keys():
            for i in item['tagList']:
                unique_tags[i] = 1
                # print(f"TAG: {i} UTAG: {unique_tags}")
    tags = list(unique_tags.keys())
    # try:
    #     last_evaluated_key = response['LastEvaluatedKey']
    #     while last_evaluated_key in response:
    #         print("IN WHILE")
    #         tags = unique_tags.keys()
    #         print(tags)
    # except Exception as e:
    #     print("Exception occurred", e)

    res = {
        'tags': tags
    }

    return envelop(res)


# used for list article
def query_enough_articles(query_params, authenticated_user, limit, offset, flag):
    query_result_item = []
    table = dynamodb.Table('dev-article')
    while len(query_result_item) < int(offset) + int(limit):
        if flag == 1:
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy = :dummy',
                FilterExpression='contains(tagList, :tag)',
                ExpressionAttributeValues={
                    ':dummy': 'OK',
                    ':tag': query_params,
                },
                ScanIndexForward=False,
            )
            query_result_item.append(query_result['Items'])
        if flag == 2:
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy = :dummy',
                FilterExpression='author= :author',
                ExpressionAttributeValues={
                    ':dummy': 'OK',
                    ':author': query_params,
                },
                ScanIndexForward=False,
            )
            query_result_item.append(query_result['Items'])
        if flag == 3:
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy = :dummy',
                FilterExpression='contains(favoritedBy, :favorited)',
                ExpressionAttributeValues={
                    ':dummy': 'OK',
                    ':favorited': query_params,
                },
                ScanIndexForward=False,
            )
            query_result_item.append(query_result['Items'])
        if flag == 0:
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy = :dummy',
                ExpressionAttributeValues={
                    ':dummy': 'OK',
                },
                ScanIndexForward=False,
            )
            query_result_item.append(query_result['Items'])
        if 'LastEvaluatedKey' in query_result_item:
            query_result = table.query(
                IndexName='updatedAt',
                KeyConditionExpression='dummy = :dummy',
                FilterExpression='author= :author',
                ExpressionAttributeValues={
                    ':dummy': 'OK',
                    ':author': query_params,
                },
                ExclusiveStartKey=query_result['LastEvaluatedKey']
            )
        else:
            break

    article_promises = []
    result = query_result_item[int(offset):int(offset) + int(limit)]
    for aa in result[0]:
        article_promises.append(transform_retrieved_article(aa, authenticated_user))
        print("PROMISES",article_promises)
    articles = article_promises

    return articles


def get_enough_article_query_tags(eav, fe, authenticated_user, offset, limit):
    query_result_item = []
    table = dynamodb.Table('dev-article')
    while len(query_result_item) < (offset + limit):
        query_result = table.query(
            IndexName='updatedAt',
            KeyConditionExpression='dummy= :dummy',
            FilterExpression='author IN'+fe,
            ExpressionAttributeValues=eav,
            ScanIndexForward=False
        )
        query_result_item.append(query_result['Items'])
        # if query_result['LastEvaluatedKey']:
        #     # filter_exp.ExclusiveStartKey = query_result.LastEvaluatedKey
        #     query_result = table.query(
        #         IndexName='updatedAt',
        #         KeyConditionExpression='dummy= :dummy',
        #         FilterExpression='author IN' + fe,
        #         ExpressionAttributeValues=eav,
        #         ScanIndexForward=False,
        #         ExclusiveStartKey=query_result['LastEvaluatedKey']
        #     )
        # else:
        #     break
        # print(f"get_enough_article_query:{query_result}")

    article_data_list = []
    res = query_result_item[offset:(offset + limit)]
    for data in res[0]:
        article_data_list.append(transform_retrieved_article(data, authenticated_user))
    articles = article_data_list
    return {'articles': articles}


def transform_retrieved_article(article, authenticated_user):
    del article['dummy']
    article['favorited'] = False
    try:
        if 'tagList' in article:
            article['tagList'] = article['tagList']
        else:
            article['tagList'] = []
        if 'favoritesCount' in article:
            article['favoritesCount'] = article['favoritesCount']
        else:
            article['favoritesCount'] = 0
        # article['favoritesCount'] = article['favoritesCount']

        if 'favoritedBy' in article and authenticated_user:
            article['favorited'] = authenticated_user['username'] in article['favoritedBy']
        article['favoritedBy'] = []
    except Exception as e:
        print(f"Exception occurred:{e} ")

    article['author'] = user.get_profile_by_username(article['author'], authenticated_user)

    return article
