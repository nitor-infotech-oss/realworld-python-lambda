import json


def envelop(res, status_code=200):
    print("IN UTIL ENVELOP")
    if status_code == 200:
        body = json.dumps(res)
    else:
        body = json.dumps({"errors":{'': res}})
    return {
        "statusCode": status_code,
        "headers": {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': 'true'
        },
        "body": body
    }
