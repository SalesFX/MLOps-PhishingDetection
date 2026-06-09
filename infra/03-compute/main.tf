provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "terraform_remote_state" "storage" {
  backend = "s3"

  config = {
    bucket = "network-security-mlops-tfstate-074994084847"
    key    = "01-storage-registry/terraform.tfstate"
    region = "us-east-1"
  }
}
