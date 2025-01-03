from queue import Queue
import sys
import os
import json
import datetime
import threading
import queue
import logging
import time
import boto3
from github_api_toolkit import github_graphql_interface, github_interface
import github_api_toolkit

# Set up logging for Lambda environment
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Clear any existing handlers
for handler in logger.handlers:
    logger.removeHandler(handler)

# Add stdout handler
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
logger.addHandler(stdout_handler)

# Configuration
org = os.getenv("GITHUB_ORG")
client_id = os.getenv("GITHUB_APP_CLIENT_ID")
repo_limit = int(os.getenv("REPO_LIMIT", "0"))  # 0 means no limit

# AWS Secret Manager Secret Name for the .pem file
secret_name = os.getenv("AWS_SECRET_NAME")
secret_reigon = os.getenv("AWS_DEFAULT_REGION")

account = os.getenv("AWS_ACCOUNT_NAME", "sdp-dev")
BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME", "sdp-dev-github-audit")

# Thread-safe queue for results
result_queue = queue.Queue()

# Add at the top with other global variables
TOTAL_RETRIEVED = 0
TOTAL_PROCESSED = 0

# Add these at the top with other global variables
THREAD_POOL_SIZE = int(os.getenv("THREAD_COUNT", "3"))
processing_queue = Queue()
processed_repos = []
processing_lock = threading.Lock()


def get_repository_security_settings(gh: github_interface, repo_name: str) -> dict:
    """
    Get security settings for a repository using REST API.
    Checks if features are enabled by attempting to list alerts.
    """
    try:
        # Check if Dependabot is enabled
        try:
            gh.get(f"/repos/{org}/{repo_name}/vulnerability-alerts")
            dependabot_enabled = True
        except Exception:
            dependabot_enabled = False

        # Check if Secret Scanning is enabled by trying to list alerts
        try:
            gh.get(f"/repos/{org}/{repo_name}/secret-scanning/alerts")
            secret_scanning_enabled = True
        except Exception:
            # 404 is expected for public repos or when disabled
            secret_scanning_enabled = False

        return {
            "dependabot_disabled": not dependabot_enabled,
            "secret_scanning_disabled": not secret_scanning_enabled,
        }
    except Exception as e:
        logger.error(f"Error getting security settings for {repo_name}: {str(e)}")
        return {"dependabot_disabled": True, "secret_scanning_disabled": True}


def process_repository_security(gh: github_interface, repo_info: dict):
    """Process security settings for a single repository"""
    try:
        security_settings = get_repository_security_settings(gh, repo_info["name"])

        with processing_lock:
            repo_info["checklist"].update(security_settings)
            processed_repos.append(repo_info)
    except Exception as e:
        logger.error(
            f"{threading.current_thread().name}: Error processing security for {repo_info['name']}: {str(e)}"
        )


def security_worker(gh: github_interface):
    """Worker function to process repositories from the queue"""
    thread_name = threading.current_thread().name
    repos_processed = 0
    logger.info(f"{thread_name}: Started security worker")

    while True:
        try:
            repo_info = processing_queue.get(timeout=1)
            if repo_info is None:  # Poison pill
                logger.info(
                    f"{thread_name}: Shutting down after processing {repos_processed} repositories"
                )
                break

            process_repository_security(gh, repo_info)
            repos_processed += 1

            with processing_lock:
                queue_size = processing_queue.qsize()
                TOTAL_PROCESSED = len(processed_repos)
                if TOTAL_PROCESSED % 5 == 0 and queue_size != 0:
                    logger.info(
                        f"Processed: {repos_processed} | "
                        f"Total processed: {TOTAL_PROCESSED} | "
                        f"Queue size: {queue_size}"
                    )

            processing_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"{thread_name}: Worker error: {str(e)}")
            continue


def get_repository_data_graphql(
    ql: github_graphql_interface, gh: github_interface, org: str, batch_size: int = 30
):
    """Gets repository data using concurrent processing"""
    start_time = time.time()
    logger.info(f"Starting repository data collection for {org}")

    # Add timeout check
    def check_timeout(
        start_time, max_duration=840
    ):  # 14 minutes, leaving 1 minute buffer
        if time.time() - start_time > max_duration:
            logger.warning("Approaching Lambda timeout, stopping processing")
            return True
        return False

    # Define GraphQL query at the start of the function
    query = """
    query($org: String!, $limit: Int!, $cursor: String) {
      organization(login: $org) {
        repositories(first: $limit, after: $cursor, isArchived: false) {
          pageInfo {
            hasNextPage
            endCursor
          }
          nodes {
            name
            url
            visibility
            createdAt
            pushedAt
            isArchived
            
            # For inactive check and unsigned commits
            defaultBranchRef {
              target {
                ... on Commit {
                  history(first: 15) {
                    nodes {
                      committedDate
                      signature {
                        isValid
                      }
                    }
                  }
                }
              }
            }
            
            # For branch protection check
            refs(refPrefix: "refs/heads/", first: 100) {
              nodes {
                name
                branchProtectionRule {
                  id
                  requiresStatusChecks
                  requiresApprovingReviews
                  dismissesStaleReviews
                }
              }
            }
            
            # For file checks (README, LICENSE, etc)
            object(expression: "HEAD:") {
              ... on Tree {
                entries {
                  name
                  path
                }
              }
            }
            
            # For external PR check
            pullRequests(first: 100, states: OPEN) {
              nodes {
                author {
                  login
                }
              }
            }
          }
        }
      }
    }
    """

    # Start worker threads
    workers = []
    logger.info(f"Starting {THREAD_POOL_SIZE} security worker threads")
    for i in range(THREAD_POOL_SIZE):
        worker = threading.Thread(
            target=security_worker, args=(gh,), name=f"thread-{i+1}"
        )
        worker.start()
        workers.append(worker)
        logger.info(f"Started thread-{i+1}")

    has_next_page = True
    cursor = None
    TOTAL_RETRIEVED = 0

    try:
        while has_next_page:
            if check_timeout(start_time):
                break

            variables = {"org": org, "limit": batch_size, "cursor": cursor}

            # Get GraphQL data with retries
            for attempt in range(3):
                result = ql.make_ql_request(query, variables)
                if not result.ok:
                    logger.error(
                        f"GraphQL query failed on attempt {attempt+1}. "
                        f"Waiting 5 seconds before retrying: {result.status_code}"
                    )
                    time.sleep(2.5)
                    continue
                data = result.json()
                if "errors" in data:
                    logger.error(
                        f"GraphQL query failed on attempt {attempt+1}: {data['errors']}"
                    )
                    if attempt < 2:
                        time.sleep(2.5)
                        continue
                break
            else:
                logger.error("All attempts to execute GraphQL query failed.")

            repos = data["data"]["organization"]["repositories"]["nodes"]
            TOTAL_RETRIEVED += len(repos)
            logger.info(
                f"Retrieved: {len(repos)} | Total repositories: {TOTAL_RETRIEVED}"
            )

            # Process basic repository data and queue for security processing
            for repo in repos:
                try:
                    # Calculate if repo is inactive
                    try:
                        history_nodes = repo["defaultBranchRef"]["target"]["history"][
                            "nodes"
                        ]
                        last_activity = datetime.datetime.strptime(
                            history_nodes[0]["committedDate"], "%Y-%m-%dT%H:%M:%SZ"
                        )
                    except (KeyError, IndexError, TypeError):
                        last_activity = datetime.datetime.strptime(
                            repo["pushedAt"], "%Y-%m-%dT%H:%M:%SZ"
                        )

                    is_inactive = (datetime.datetime.now() - last_activity).days > 365

                    # Check branch protection
                    unprotected_branches = False
                    for branch in repo["refs"]["nodes"]:
                        protection = branch.get("branchProtectionRule")
                        if not protection or not all(
                            [
                                protection.get("requiresStatusChecks"),
                                protection.get("requiresApprovingReviews"),
                                protection.get("dismissesStaleReviews"),
                            ]
                        ):
                            unprotected_branches = True
                            break

                    # Check unsigned commits
                    unsigned_commits = any(
                        not commit.get("signature", {}).get("isValid")
                        for commit in history_nodes
                        if commit and commit.get("signature")
                    )

                    # Get all file paths for file checks
                    files = []
                    if repo.get("object") and repo["object"].get("entries"):
                        files = [
                            entry["path"].lower() for entry in repo["object"]["entries"]
                        ]

                    # File checks
                    readme_missing = not any("readme.md" in f for f in files)
                    license_missing = not any(
                        f in ["license.md", "license"] for f in files
                    )
                    pirr_missing = not any("pirr.md" in f for f in files)
                    gitignore_missing = not any(".gitignore" in f for f in files)
                    codeowners_missing = not any(
                        f in [".github/codeowners", "codeowners", "docs/codeowners"]
                        for f in files
                    )

                    # Check for external PRs
                    pr_authors = [
                        pr["author"]["login"]
                        for pr in repo["pullRequests"]["nodes"]
                        if pr["author"]
                    ]
                    external_pr = any(
                        author != "dependabot[bot]" for author in pr_authors
                    )

                    repo_info = {
                        "name": repo["name"],
                        "type": repo["visibility"].lower(),
                        "url": repo["url"],
                        "created_at": repo["createdAt"],
                        "checklist": {
                            "inactive": is_inactive,
                            "unprotected_branches": unprotected_branches,
                            "unsigned_commits": unsigned_commits,
                            "readme_missing": readme_missing,
                            "license_missing": license_missing,
                            "pirr_missing": pirr_missing,
                            "gitignore_missing": gitignore_missing,
                            "external_pr": external_pr,
                            "breaks_naming_convention": any(
                                c.isupper() for c in repo["name"]
                            ),
                            "secret_scanning_disabled": None,  # Will be set by worker
                            "dependabot_disabled": None,  # Will be set by worker
                            "codeowners_missing": codeowners_missing,
                            "point_of_contact_missing": codeowners_missing,
                        },
                    }

                    # Adjust checks based on visibility
                    if repo_info["type"] == "public":
                        repo_info["checklist"]["pirr_missing"] = False
                    else:
                        repo_info["checklist"]["license_missing"] = False

                    # Add to processing queue
                    logger.debug(
                        f"Queueing {repo['name']} for security processing (Queue size: {processing_queue.qsize()})"
                    )
                    processing_queue.put(repo_info)

                except Exception as e:
                    logger.error(
                        f"Error processing repository {repo.get('name', 'unknown')}: {str(e)}"
                    )

            # Update pagination
            has_next_page = data["data"]["organization"]["repositories"]["pageInfo"][
                "hasNextPage"
            ]
            cursor = data["data"]["organization"]["repositories"]["pageInfo"][
                "endCursor"
            ]

            if repo_limit and TOTAL_RETRIEVED >= repo_limit:
                break

        # Add timeout check before worker cleanup
        if check_timeout(start_time):
            logger.warning("Timeout reached during processing")

    finally:
        cleanup_start = time.time()
        logger.info("Starting worker cleanup")
        # Send poison pills to workers
        logger.info("Sending shutdown signal to security workers")
        for _ in range(THREAD_POOL_SIZE):
            processing_queue.put(None)

        # Wait for all security processing to complete
        logger.info("Waiting for security workers to complete...")
        for worker in workers:
            worker.join()
        logger.info("All security workers have completed")
        logger.info(f"Cleanup completed in {time.time() - cleanup_start:.2f} seconds")

    # Remove local file writing, just return the processed repos
    duration = time.time() - start_time
    logger.info(
        f"Total processing time: {duration:.2f} seconds ({duration/60:.2f} minutes)"
    )

    return processed_repos


def lambda_handler(event, context):
    """
    AWS Lambda handler function for GitHub repository audit
    """
    try:
        start_time = time.time()
        logger.info("Starting GitHub repository audit Lambda")

        if repo_limit:
            logger.info(f"Will process up to {repo_limit} repositories")

        session = boto3.Session()
        secret_manager = session.client("secretsmanager", region_name=secret_reigon)

        logger.info("Getting GitHub token from AWS Secrets Manager")
        secret = secret_manager.get_secret_value(SecretId=secret_name)["SecretString"]

        token = github_api_toolkit.get_token_as_installation(org, secret, client_id)
        if not token:
            logger.error("Error getting GitHub token")
            return {"statusCode": 500, "body": json.dumps("Failed to get GitHub token")}

        logger.info("Successfully obtained GitHub token")
        ql = github_graphql_interface(str(token[0]))
        gh = github_interface(str(token[0]))

        # Get token
        token_start = time.time()
        # ... token getting code ...
        logger.info(f"Token retrieval took {time.time() - token_start:.2f} seconds")

        # Get repos
        repo_start = time.time()
        repos = get_repository_data_graphql(ql, gh, org)
        logger.info(
            f"Repository processing took {time.time() - repo_start:.2f} seconds"
        )

        # Upload to S3
        upload_start = time.time()
        # Upload results to S3
        s3_client = session.client("s3")
        output_data = {
            "repositories": repos,
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "repository_count": len(repos),
                "organization": org,
            },
        }

        try:
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key="repositories.json",
                Body=json.dumps(output_data, indent=2, default=str),
                ContentType="application/json",
            )
            logger.info(
                f"Successfully uploaded results to s3://{BUCKET_NAME}/repositories.json"
            )
        except Exception as e:
            logger.error(f"Failed to upload to S3: {str(e)}")
            raise
        logger.info(f"S3 upload took {time.time() - upload_start:.2f} seconds")

        total_duration = time.time() - start_time
        logger.info(f"Total execution time: {total_duration:.2f} seconds")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Successfully processed repositories",
                    "repository_count": len(repos),
                    "execution_time_seconds": total_duration,
                }
            ),
        }

    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Lambda execution failed: {str(e)}"),
        }
