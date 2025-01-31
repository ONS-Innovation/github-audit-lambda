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
}

variable "service_subdomain" {
  description = "Service subdomain"
  type        = string
  default     = "github-audit"
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

variable "source_bucket" {
  description = "Source S3 bucket name"
  type        = string
  default     = "sdp-dev-github-audit"
}

variable "source_key" {
  description = "Source JSON file key"
  type        = string
  default     = "repositories.json"
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

variable "ecr_repository_name" {
  description = "Name of the ECR repository"
  type        = string
  default     = "sdp-dev-github-audit"
}

variable "cron_job_schedule" {
  description = "Cron job schedule"
  type        = string
  default     = "cron(0 12 * * ? *)"
}

variable "github_app_client_id" {
  description = "Github App Client ID"
  type        = string
  sensitive   = true
}

variable "aws_secret_name" {
  description = "AWS Secret Name"
  type        = string
}

variable "github_org" {
  description = "Github Org"
  type        = string
}

variable "thread_count" {
  description = "Thread count for the lambda"
  type        = number
  default     = 3
}
