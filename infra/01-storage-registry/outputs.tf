output "app_bucket_name" {
  description = "Name of the S3 bucket for ML artifacts. Use as AWS_S3_BUCKET_NAME env var."
  value       = aws_s3_bucket.app.id
}

output "app_bucket_arn" {
  description = "ARN of the app S3 bucket"
  value       = aws_s3_bucket.app.arn
}

output "ecr_repository_name" {
  description = "ECR repository name. Copy to GitHub Secret ECR_REPOSITORY_NAME."
  value       = aws_ecr_repository.app.name
}

output "ecr_repository_url" {
  description = "Full ECR repository URL (account/region/repo)"
  value       = aws_ecr_repository.app.repository_url
}

output "ecr_registry" {
  description = "ECR registry host only. Copy to GitHub Secret ECR_REGISTRY."
  value       = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
}

output "ecr_repository_arn" {
  description = "ECR repository ARN"
  value       = aws_ecr_repository.app.arn
}
