# realworld-python-lambda
This application is based on AWS Lambda function,DynamoDB,API Gateway using serverless framework with python

# **Getting started**


Clone this repo:
```
git clone https://github.com/nitor-infotech-oss/realworld-python-lambda.git
```
# Serverless Framework

# Setup

1     # Step 1. Install serverless globally
```
        npm install -g serverless
```
2     # Step 2.Create a new Serverless Service/Project
```
        sls create --template aws-python3 --path realworld-python-lambda
        cd realworld-python-lambda
```
3     # Deploy, test and diagnose your service

a.Deploy the Service:
Use this when you have made changes to your Functions, Events or Resources in serverless.yml or you simply want to deploy all changes within your Service at the same time.
```
        sls deploy -v
```
b. Deploy the Function:
Use this to quickly upload and overwrite your function code, allowing you to develop faster.
```
        sls deploy function -f hello
```

