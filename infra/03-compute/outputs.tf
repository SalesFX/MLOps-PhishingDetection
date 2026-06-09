output "ec2_public_ip" {
  description = "Public IP of the EC2 instance. Copy to GitHub Secret EC2_HOST."
  value       = aws_instance.app.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of the EC2 instance"
  value       = aws_instance.app.public_dns
}

output "security_group_id" {
  description = "ID of the application security group"
  value       = aws_security_group.app.id
}

output "instance_id" {
  description = "ID of the EC2 instance"
  value       = aws_instance.app.id
}
