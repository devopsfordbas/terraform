variable "bucket_name" {
  description = "Bucket name were the bastion will store the logs"
}

variable "bucket_versioning" {
  default     = true
  description = "Enable bucket versioning or not"
}

variable "bucket_force_destroy" {
  default     = false
  description = "The bucket and all objects should be destroyed when using true"
}

variable "tags" {
  description = "A mapping of tags to assign"
  default     = {}
  type        = map(string)
}

variable "region" {
}

variable "cidrs" {
  description = "List of CIDRs than can access to the bastion. Default : 0.0.0.0/0"
  type        = list(string)

  default = [
    "0.0.0.0/0",
  ]
}

variable "vpc_id" {
  description = "VPC id were we'll deploy the bastion"
}

variable "bastion_host_key_pair" {
  description = "Select the key pair to use to launch the bastion host"
}

variable "hosted_zone_id" {
  description = "Name of the hosted zone were we'll register the bastion DNS name"
  default     = ""
}

variable "bastion_record_name" {
  description = "DNS record name to use for the bastion"
  default     = ""
}

variable "bastion_launch_template_name" {
  description = "Bastion Launch template Name, will also be used for the ASG"
  default     = "bastion-lt"
}

variable "bastion_ami" {
  type        = string
  description = "The AMI that the Bastion Host will use."
  default     = ""
}

variable "associate_public_ip_address" {
  default = true
}

variable "bastion_instance_count" {
  default = 1
}

variable "create_dns_record" {
  description = "Choose if you want to create a record name for the bastion (LB). If true 'hosted_zone_id' and 'bastion_record_name' are mandatory "
}

variable "log_auto_clean" {
  description = "Enable or not the lifecycle"
  default     = false
}

variable "log_expiry_days" {
  description = "Number of days before logs expiration"
  default     = 90
}

variable "public_ssh_port" {
  description = "Set the SSH port to use from desktop to the bastion"
  default     = 22
}

variable "private_ssh_port" {
  description = "Set the SSH port to use between the bastion and private instance"
  default     = 22
}

variable "extra_user_data_content" {
  description = "Additional scripting to pass to the bastion host. For example, this can include installing postgresql for the `psql` command."
  type        = string
  default     = ""
}

variable "allow_ssh_commands" {
  description = "Allows the SSH user to execute one-off commands. Pass 'True' to enable. Warning: These commands are not logged and increase the vulnerability of the system. Use at your own discretion."
  type        = string
  default     = ""
}
