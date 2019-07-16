# refarch-webapp-serverless
This application is based on AWS Lambda function,DynamoDB,API Gateway using serverless framework with python

# **Getting started**


Clone this repo:
```
git clone https://github.com/nitor-infotech-oss/refarch-webapp-serverless.git
```
# Serverless Framework

# Setup

1     # Step 1. Install serverless globally
```
        npm install -g serverless
```
2     # Step 2.Create a new Serverless Service/Project
```
        sls create --template aws-python3 --path refarch-webapp-serverless
        cd refarch-webapp-serverless
```
3     # Deploy, test and diagnose your service

a.Deploy the Service:
Use this when you have made changes to your Functions, Events or Resources in serverless.yml or you simply want to deploy all changes within your Service at the same time.
```
        serverless deploy -v
```
b. Deploy the Function:
Use this to quickly upload and overwrite your function code, allowing you to develop faster.
```
        serverless deploy function -f hello
```

