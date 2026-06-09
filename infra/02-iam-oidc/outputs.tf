output "github_actions_role_arn" {
  description = "ARN of the GitHub Actions IAM role. Copy to GitHub Secret AWS_ROLE_ARN."
  value       = aws_iam_role.github_actions.arn
}
