from queue import Queue
import sys
import os
import json
import datetime
import threading
import queue
import requests.exceptions
import logging
import time
import boto3
from github_api_toolkit import github_graphql_interface, github_interface
import github_api_toolkit
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

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

    Args:
        gh: github_interface
        repo_name: str

    Returns:
        dict: security settings
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


def get_secret_scanning_alerts(gh: github_interface, repo_name: str) -> list:
    """Get secret scanning alerts for a repository
    
    Args:
        gh: github_interface
        repo_name: str

    Returns:
        list: secret scanning alerts
    """
    alerts = []
    try:
        response = gh.get(f"/repos/{org}/{repo_name}/secret-scanning/alerts")
        if response.ok:
            for alert in response.json():
                alerts.append(
                    {
                        "repo": repo_name,
                        "created_at": alert["created_at"],
                        "secret": alert["secret_type_display_name"],
                        "link": alert["html_url"],
                    }
                )
        elif response.status_code == 404:
            # Repository doesn't have secret scanning enabled or is public
            logger.debug(f"Secret scanning not available for {repo_name}")
    except AttributeError:
        # Non-fatal error, so we can continue
        pass
    except Exception as e:
        logger.error(
            f"{e.__class__.__name__}: Error getting secret scanning alerts for {repo_name}: {str(e)}"
        )
    return alerts


def get_dependabot_alerts(gh: github_interface, repo_name: str) -> list:
    """Get Dependabot alerts for a repository
    
    Args:
        gh: github_interface
        repo_name: str

    Returns:
        list: dependabot alerts
    """
    alerts = []
    try:
        response = gh.get(f"/repos/{org}/{repo_name}/dependabot/alerts")
        if response.ok:
            for alert in response.json():
                alerts.append(
                    {
                        "repo": repo_name,
                        "created_at": alert["created_at"],
                        "severity": alert["security_advisory"]["severity"],
                        "package": alert["security_advisory"]["package"]["name"],
                        "description": alert["security_advisory"]["description"],
                        "link": alert["html_url"],
                    }
                )
    except Exception as e:
        logger.error(f"Error getting Dependabot alerts for {repo_name}: {str(e)}")
    return alerts


def process_repository_security(gh: github_interface, repo_info: dict):
    """Process security settings for a single repository
    
    Args:
        gh: github_interface
        repo_info: dict
    
    Returns:
        None
    """
    try:
        security_settings = get_repository_security_settings(gh, repo_info["name"])

        # Get secret scanning alerts if enabled
        if not security_settings["secret_scanning_disabled"]:
            repo_info["secret_scanning_alerts"] = get_secret_scanning_alerts(
                gh, repo_info["name"]
            )

        with processing_lock:
            repo_info["checklist"].update(security_settings)
            processed_repos.append(repo_info)
    except Exception as e:
        logger.error(
            f"{threading.current_thread().name}: Error processing security for {repo_info['name']}: {str(e)}"
        )


def security_worker(gh: github_interface):
    """Worker function to process repositories from the queue
    
    Args:
        gh: github_interface
    
    Returns:
        None
    """
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

def check_is_inactive(repo):
    # Calculate if repo is inactive
    try:
        if not repo.get("defaultBranchRef"):
            # logger.warning(f"No default branch ref for repo {repo.get('name')}")
            return False
            
        if not repo["defaultBranchRef"].get("target"):
            # logger.warning(f"No target in default branch ref for repo {repo.get('name')}")
            return False
            
        if not repo["defaultBranchRef"]["target"].get("history"):
            # logger.warning(f"No history in target for repo {repo.get('name')}")
            return False
            
        history_nodes = repo["defaultBranchRef"]["target"]["history"]["nodes"]
        if not history_nodes:
            # logger.warning(f"No history nodes for repo {repo.get('name')}, using pushedAt")
            raise KeyError("No history nodes")
            
        last_activity = datetime.datetime.strptime(
            history_nodes[0]["committedDate"], "%Y-%m-%dT%H:%M:%SZ"
        )
    except (KeyError, IndexError, TypeError) as e:
        logger.debug(f"Falling back to pushedAt for repo {repo.get('name')} due to: {str(e)}")
        if not repo.get("pushedAt"):
            # logger.warning(f"No pushedAt for repo {repo.get('name')}")
            return False
        last_activity = datetime.datetime.strptime(
            repo["pushedAt"], "%Y-%m-%dT%H:%M:%SZ"
        )

    is_inactive = (
        datetime.datetime.now() - last_activity
    ).days > 365

    return is_inactive

def has_unprotected_branches(repo):
    # Check branch protection
    try:
        if not repo.get("refs") or not repo["refs"].get("nodes"):
            # logger.warning(f"No refs/nodes for repo {repo.get('name')}")
            return True
            
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
        return unprotected_branches
    except Exception as e:
        logger.error(f"Error checking branch protection for {repo.get('name')}: {str(e)}")
        return True

def check_unsigned_commits(repo):
    # Check unsigned commits
    try:
        if not repo.get("defaultBranchRef") or not repo["defaultBranchRef"].get("target") or \
           not repo["defaultBranchRef"]["target"].get("history") or \
           not repo["defaultBranchRef"]["target"]["history"].get("nodes"):
            # logger.warning(f"Missing commit history structure for repo {repo.get('name')}")
            return False
            
        unsigned_commits = any(
            not commit.get("signature", {}).get("isValid")
            for commit in repo["defaultBranchRef"]["target"]["history"]["nodes"]
            if commit and commit.get("signature")
        )
        return unsigned_commits
    except Exception as e:
        logger.error(f"Error checking unsigned commits for {repo.get('name')}: {str(e)}")
        return False

def get_all_file_paths(repo):
    # Get all file paths for file checks
    try:
        if not repo.get("object"):
            # logger.warning(f"No object data for repo {repo.get('name')}")
            return []
            
        if not repo["object"].get("entries"):
            # logger.warning(f"No entries in object for repo {repo.get('name')}")
            return []
            
        return [entry["path"].lower() for entry in repo["object"]["entries"]]
    except Exception as e:
        logger.error(f"Error getting file paths for {repo.get('name')}: {str(e)}")
        return []

def check_dependabot_alerts(repo):
    # Process vulnerability alerts
    dependabot_alerts = []
    try:
        if not repo.get("vulnerabilityAlerts"):
            logger.debug(f"No vulnerability alerts object for repo {repo.get('name')}")
            return dependabot_alerts
            
        if not repo["vulnerabilityAlerts"].get("nodes"):
            logger.debug(f"No vulnerability alert nodes for repo {repo.get('name')}")
            return dependabot_alerts
            
        for alert in repo["vulnerabilityAlerts"]["nodes"]:
            try:
                if not alert or alert.get("dismissedAt"):  # Skip dismissed alerts
                    continue
                    
                if not alert.get("createdAt"):
                    # logger.warning(f"Alert missing createdAt for repo {repo.get('name')}")
                    continue
                    
                if not alert.get("securityVulnerability"):
                    # logger.warning(f"Alert missing securityVulnerability for repo {repo.get('name')}")
                    continue
                    
                created_at = datetime.datetime.strptime(
                    alert["createdAt"], "%Y-%m-%dT%H:%M:%SZ"
                )
                days_open = (
                    datetime.datetime.now() - created_at
                ).days

                dependabot_alerts.append(
                    {
                        "repo": repo["name"],
                        "created_at": alert["createdAt"],
                        "dependency": alert["securityVulnerability"]["package"]["name"],
                        "advisory": alert["securityVulnerability"]["advisory"]["description"],
                        "severity": alert["securityVulnerability"]["severity"].lower(),
                        "days_open": days_open,
                        "link": f"https://github.com/{org}/{repo['name']}/security/dependabot/{len(dependabot_alerts) + 1}",
                    }
                )
            except Exception as e:
                logger.error(f"Error processing individual alert for {repo.get('name')}: {str(e)}")
                continue
                
    except Exception as e:
        logger.error(f"Error processing dependabot alerts for {repo.get('name')}: {str(e)}")
    return dependabot_alerts


def check_missing_file(files, file_name):
    # Check for missing file
    return not any(file_name in f for f in files)

def get_repository_data_graphql(
    ql: github_graphql_interface, gh: github_interface, org: str, batch_size: int = 25
):
    """Gets repository data using concurrent processing
    
    Args:
        ql: github_graphql_interface
        gh: github_interface
        org: str
        batch_size: int

    Returns:
        list: processed repositories
    """
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
            hasVulnerabilityAlertsEnabled
            
            vulnerabilityAlerts(first: 100) {
              nodes {
                createdAt
                dismissedAt
                securityVulnerability {
                  severity
                  package {
                    name
                  }
                  advisory {
                    description
                  }
                }
              }
            }
            
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
        worker.daemon = True  # Make threads daemon so they don't block shutdown
        worker.start()
        workers.append(worker)

    has_next_page = True
    cursor = None
    TOTAL_RETRIEVED = 0

    try:
        while has_next_page:
            if check_timeout(start_time):
                break

            variables = {"org": org, "limit": batch_size, "cursor": cursor}

            # Get GraphQL data with retries and exponential backoff
            for attempt in range(5):  # Increased retry attempts
                try:
                    result = ql.make_ql_request(query, variables)
                    if not result.ok:
                        if result.status_code in [403, 429]:  # Rate limit exceeded
                            wait_time = min(
                                2**attempt, 32
                            )  # Exponential backoff capped at 32 seconds
                            logger.warning(
                                f"Rate limit hit on attempt {attempt+1}. "
                                f"Waiting {wait_time} seconds before retrying."
                            )
                            time.sleep(wait_time)
                            continue
                        logger.error(
                            f"GraphQL query failed on attempt {attempt+1} with status {result.status_code}"
                        )
                        time.sleep(1)
                        continue

                    data = result.json()
                    if "errors" in data:
                        logger.error(
                            f"GraphQL query failed on attempt {attempt+1}: {data['errors']}"
                        )
                        if attempt < 4:  # Allow for one more retry
                            time.sleep(1)
                            continue
                    break
                except (
                    requests.exceptions.RequestException,
                    requests.exceptions.ConnectionError,
                ) as e:
                    if attempt == 4:  # Last attempt
                        logger.error(f"Failed all retry attempts: {str(e)}")
                        raise
                    wait_time = min(2**attempt, 32)
                    logger.warning(
                        f"Request failed with {e.__class__.__name__}, retrying in {wait_time}s"
                    )
                    time.sleep(wait_time)
            else:
                logger.error("All attempts to execute GraphQL query failed.")
                continue  # Skip this batch but continue with next cursor

            # Process the successful response
            try:
                repos = data["data"]["organization"]["repositories"]["nodes"]
                TOTAL_RETRIEVED += len(repos)
                logger.info(
                    f"Retrieved: {len(repos)} | Total repositories: {TOTAL_RETRIEVED}"
                )

                # Update pagination before processing
                has_next_page = data["data"]["organization"]["repositories"][
                    "pageInfo"
                ]["hasNextPage"]
                cursor = data["data"]["organization"]["repositories"]["pageInfo"][
                    "endCursor"
                ]

                # Process repositories
                for repo in repos:
                    try:
                        is_inactive = check_is_inactive(repo)

                        unprotected_branches = has_unprotected_branches(repo)

                        unsigned_commits = check_unsigned_commits(repo)

                        files = get_all_file_paths(repo)

                        dependabot_alerts = check_dependabot_alerts(repo)

                        # File checks
                        readme_missing = check_missing_file(files, "readme.md")
                        license_missing = check_missing_file(files, "license.md")
                        pirr_missing = check_missing_file(files, "pirr.md")
                        gitignore_missing = check_missing_file(files, ".gitignore")

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
                            "dependabot_alerts": dependabot_alerts,
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
                                "dependabot_disabled": not repo.get(
                                    "hasVulnerabilityAlertsEnabled", False
                                ),
                                "codeowners_missing": codeowners_missing,
                                "point_of_contact_missing": codeowners_missing,
                            },
                        }

                        # Adjust checks based on visibility
                        if repo_info["type"] == "public":
                            repo_info["checklist"]["pirr_missing"] = False
                        else:
                            repo_info["checklist"]["license_missing"] = False

                        # Add to processing queue with timeout
                        try:
                            processing_queue.put(repo_info, timeout=5)
                        except queue.Full:
                            logger.error(
                                f"Queue full, skipping repository {repo['name']}"
                            )
                            continue

                    except Exception as e:
                        logger.error(
                            f"{e.__class__.__name__}: Error processing repository {repo.get('name', 'unknown')}: {str(e)}"
                        )
                        continue  # Skip this repo but continue with others

            except (KeyError, TypeError) as e:
                logger.error(f"Error parsing GraphQL response: {str(e)}")
                continue  # Skip this batch but continue with next cursor

            if repo_limit and TOTAL_RETRIEVED >= repo_limit:
                break

    except Exception as e:
        logger.error(f"Fatal error in repository processing: {str(e)}")
    finally:
        cleanup_start = time.time()
        logger.info("Starting worker cleanup")

        # Set a flag to stop processing
        global should_stop_processing
        should_stop_processing = True

        # Clear the queue and send stop signals
        try:
            while not processing_queue.empty():
                try:
                    processing_queue.get_nowait()
                except queue.Empty:
                    break

            # Send poison pills to workers
            logger.info("Sending shutdown signal to security workers")
            for _ in range(THREAD_POOL_SIZE):
                try:
                    processing_queue.put(None, timeout=1)
                except queue.Full:
                    pass
        except Exception as e:
            logger.error(f"Error during queue cleanup: {str(e)}")

        # Wait for workers with timeout
        logger.info("Waiting for security workers to complete...")
        for worker in workers:
            worker.join(timeout=10)  # Give each thread 10 seconds to finish
            if worker.is_alive():
                logger.warning(f"Worker {worker.name} did not shut down cleanly")

        logger.info("All security workers have completed or timed out")
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

    Args:
        event: dict
        context: dict

    Returns:
        dict: response
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
        s3_client = session.client("s3")

        # Extract alerts into separate lists
        secret_scanning_alerts = []
        dependabot_alerts = []
        for repo in repos:
            if "secret_scanning_alerts" in repo:
                secret_scanning_alerts.extend(repo["secret_scanning_alerts"])
                del repo["secret_scanning_alerts"]
            if "dependabot_alerts" in repo:
                dependabot_alerts.extend(repo["dependabot_alerts"])
                del repo["dependabot_alerts"]

        # Upload main repository data
        output_data = {
            "repositories": repos,
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "repository_count": len(repos),
                "organization": org,
            },
        }

        try:
            # Upload main repository data
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key="repositories.json",
                Body=json.dumps(output_data, indent=2, default=str),
                ContentType="application/json",
            )
            logger.info(
                f"Successfully uploaded results to s3://{BUCKET_NAME}/repositories.json"
            )

            # Upload secret scanning alerts
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key="secret_scanning.json",
                Body=json.dumps(secret_scanning_alerts, indent=2, default=str),
                ContentType="application/json",
            )
            logger.info(
                f"Successfully uploaded secret scanning alerts to s3://{BUCKET_NAME}/secret_scanning.json"
            )

            # Upload dependabot alerts
            s3_client.put_object(
                Bucket=BUCKET_NAME,
                Key="dependabot.json",
                Body=json.dumps(dependabot_alerts, indent=2, default=str),
                ContentType="application/json",
            )
            logger.info(
                f"Successfully uploaded dependabot alerts to s3://{BUCKET_NAME}/dependabot.json"
            )

        except Exception as e:
            logger.error(f"Failed to upload to S3: {str(e)}")
            raise

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


if __name__ == "__main__":

    # Simulate Lambda event and context
    test_event = {}
    test_context = None

    # Call the handler
    lambda_handler(test_event, test_context)
