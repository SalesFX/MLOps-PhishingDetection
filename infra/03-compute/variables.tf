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

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "key_name" {
  description = "Name of the EC2 key pair already created in AWS"
  type        = string
  nullable    = false
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into the instance. Use YOUR_IP/32."
  type        = string
  nullable    = false
}

variable "allowed_app_cidr" {
  description = "CIDR block allowed to reach the app on port 8080"
  type        = string
  default     = "0.0.0.0/0"
}
