# Default variables

variable "aws_account_id" {
  description = "AWS Account ID"
  type        = string
}

variable "aws_access_key_id" {
  description = "AWS Access Key ID"
  type        = string
}

variable "aws_secret_access_key" {
  description = "AWS Secret Access Key"
  type        = string
  sensitive   = true
}

variable "service_subdomain" {
  description = "Service subdomain"
  type        = string
  default     = "github-scraper"
}

variable "domain" {
  description = "Domain"
  type        = string
  default     = "sdp-dev"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "container_ver" {
  description = "Container tag"
  type        = string
  default     = "v0.0.1"
}

variable "project_tag" {
  description = "Project"
  type        = string
  default     = "GHA"
}

variable "team_owner_tag" {
  description = "Team Owner"
  type        = string
  default     = "Knowledge Exchange Hub"
}

variable "business_owner_tag" {
  description = "Business Owner"
  type        = string
  default     = "DST"
}

# EventBridge Lambda variables

variable "ecr_repository_name" {
  description = "Name of the ECR repository"
  type        = string
  default     = "sdp-dev-github-scraper"
}

variable "schedule" {
  description = "Schedule"
  type        = string
  default     = "cron(0 6 ? * MON,FRI *)"
}

variable "log_retention_days" {
  description = "Lambda log retention in days"
  type        = number
  default     = 7
}

variable "lambda_arch" {
  description = "Lambda architecture"
  type        = string
  default     = "arm64"
}


# Project specific variables

variable "AWS_S3_BUCKET_NAME" {
  description = "Source S3 bucket name"
  type        = string
  default     = "sdp-dev-github-audit"
}

variable "github_app_client_id" {
  description = "Github App Client ID"
  type        = string
  sensitive   = true
}

variable "aws_secret_name" {
  description = "Name of the AWS Secrets Manager secret containing the GitHub private key"
  type        = string
}

variable "github_org" {
  description = "GitHub organization name"
  type        = string
}

variable "batch_size" {
  description = "Batch size when requesting repositories from Github"
  type        = number
  default     = 30
}

variable "thread_count" {
  description = "Number of threads to use for processing"
  type        = number
  default     = 3
}
