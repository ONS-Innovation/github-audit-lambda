resource "aws_iam_policy" "secrets_access" {
  name        = "github-audit-secrets-access"
  description = "Policy to allow access to Secrets Manager for GitHub Audit"
  policy      = data.aws_iam_policy_document.secrets_policy.json
}

resource "aws_iam_policy" "s3_access" {
  name        = "github-audit-s3-access"
  description = "Policy to allow access to S3 for GitHub Audit"
  policy      = data.aws_iam_policy_document.s3_policy.json
}

module "batch_eventbridge" {
  source = "git::https://github.com/ONS-Innovation/keh-scheduled-batch-tf-module.git?ref=test-v0.0.4"

  aws_account_id     = var.aws_account_id
  aws_access_key_id  = var.aws_access_key_id
  aws_secret_access_key = var.aws_secret_access_key
  environment        = "sdp-dev"
  service_name       = "github-audit"
  region            = "eu-west-2"
  project_tag       = "sdp"
  team_owner_tag    = "sdp"
  business_owner_tag = "sdp"
  ecr_repository_name = "sdp-dev-github-audit"
  container_ver      = var.container_ver
  schedule     = var.schedule

  service_environment_variables = [
    {
      name  = "SOURCE_BUCKET"
      value = var.AWS_S3_BUCKET_NAME
    },
    {
      name  = "GITHUB_APP_CLIENT_ID"
      value = var.github_app_client_id
    },
    {
      name  = "AWS_SECRET_NAME"
      value = var.aws_secret_name
    },
    {
      name  = "GITHUB_ORG"
      value = var.github_org
    },
    {
      name  = "THREAD_COUNT"
      value = var.thread_count
    }
  ]
}

resource "aws_iam_role_policy_attachment" "secrets_policy_attachment" {
  role       = split("/", module.batch_eventbridge.batch_job_role_arn)[1]
  policy_arn = aws_iam_policy.secrets_access.arn
}

resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = split("/", module.batch_eventbridge.batch_job_role_arn)[1]
  policy_arn = aws_iam_policy.s3_access.arn
}