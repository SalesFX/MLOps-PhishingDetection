variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used as prefix for resource names"
  type        = string
  default     = "network-security-mlops"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "github_owner" {
  description = "GitHub repository owner (username or org)"
  type        = string
  nullable    = false
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  nullable    = false
}

variable "github_branch" {
  description = "GitHub branch allowed to assume the OIDC role"
  type        = string
  default     = "main"
}
