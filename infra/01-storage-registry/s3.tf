locals {
  app_bucket_name = "${var.project_name}-app-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket" "app" {
  bucket = local.app_bucket_name

  tags = merge(local.tags, {
    Name = local.app_bucket_name
  })
}
