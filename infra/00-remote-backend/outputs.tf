output "tfstate_bucket_name" {
  description = "Name of the S3 bucket for Terraform remote state. Use this value in backend.tf of all other stacks."
  value       = aws_s3_bucket.tfstate.id
}

output "tfstate_dynamodb_table_name" {
  description = "Name of the DynamoDB table for state locking."
  value       = aws_dynamodb_table.tfstate_lock.name
}

output "aws_region" {
  description = "AWS region where the backend resources were created."
  value       = var.aws_region
}
