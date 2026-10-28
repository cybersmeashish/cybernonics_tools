variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "kill_switch_mode" {
  type    = string
  default = "stop"
}

variable "alert_email_addresses" {
  type    = list(string)
  default = []
}
