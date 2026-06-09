provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

data "terraform_remote_state" "storage" {
  backend = "s3"

  config = {
    bucket = "network-security-mlops-tfstate-074994084847"
    key    = "01-storage-registry/terraform.tfstate"
    region = "us-east-1"
  }
}
