terraform {
  required_version = ">= 1.6"

  backend "s3" {
    bucket         = "network-security-mlops-tfstate-074994084847"
    key            = "02-iam-oidc/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "network-security-mlops-tfstate-lock"
    encrypt        = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
