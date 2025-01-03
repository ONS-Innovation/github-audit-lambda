# GitHub Audit Lambda 

This repository contains the investigation of the rewrite for the GitHub Audit Lambda function. This aims to improve speed and efficiency so all repositories in the organization can be audited within 15 minutes (Lambda runtime limit).


### Current metrics

| Metric | Value Locally | Value on AWS Lambda |
| --- | --- | --- |
| Current processing time | 344.45 seconds (5.74 minutes) | 421.70 seconds (7.03 minutes) |
| Current total repositories | 2187 | 2187 |
| Per repository | 0.157 seconds | 0.192 seconds |

### Explanation

Uses GitHub GraphQL API to get the repositories.
Uses GitHub RESTful API to process the repositories in parallel.
Saves the repositories to a `repositories.json` file in an S3 bucket.

### How to build and run in docker

1. Build the docker image

```bash
docker build -t <image_name> app.py
```

2. Run the docker image

```bash
docker run --platform linux/amd64 -p 9000:8080 \
-e GITHUB_ORG=<ONSDigital/ONS-innovation> \
-e GITHUB_APP_CLIENT_ID=<> \
-e AWS_SECRET_NAME=<> \
-e AWS_ACCESS_KEY_ID=<> \
-e AWS_SECRET_ACCESS_KEY=<> \
-e AWS_DEFAULT_REGION=<> \
-e AWS_ACCOUNT_NAME=<> \
-e AWS_S3_BUCKET_NAME=<sdp-dev-github-audit> \
-e REPO_LIMIT=<> \
-e THREAD_COUNT=<3> \
<image_name>
```

#### Optional environment variables

Set `REPO_LIMIT` to 0 to fetch all repositories.

Set `THREAD_COUNT` to the number of threads to use. Recommended to set to 3.

### How to lint

Linting runs `black`, `ruff` and `pylint`.

1. Install the dependencies

```bash
make install-dev
```

2. Run the linting

```bash
make lint
```
