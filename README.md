# GitHub Audit Lambda 

This repository contains the investigation of the rewrite for the GitHub Audit Lambda function. This aims to improve speed and efficiency so all repositories in the organization can be audited within 15 minutes (Lambda runtime limit).


### Current metrics

| Metric | Value |
| --- | --- |
| Current processing time | 344.45 seconds (5.74 minutes) |
| Current total repositories | 2187 |
| Per repository | 0.157 seconds |

### Explanation

Uses github graphql api to get the repositories.
Uses github rest api threading to process the repositories in parallel with the github graphql api.
Saves the repositories to a repositories.json file.

### How to run

1. Clone the repository
2. Install the dependencies

```bash
make install
```

3. Import the environment variables

```bash
export AWS_ACCESS_KEY_ID=<>
export AWS_SECRET_ACCESS_KEY=<>
export GITHUB_APP_CLIENT_ID=<>
export AWS_SECRET_NAME=<>
```

4. Run the script

```bash
make run
```

