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

variable "ecr_repository_name" {
  description = "Name of the ECR repository"
  type        = string
  default     = "network-security"
}
