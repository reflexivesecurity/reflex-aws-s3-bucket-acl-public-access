module "reflex_aws_s3_bucket_acl_public_access" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.8"
  rule_name        = "S3BucketAclPublicAccess"
  rule_description = "Detect when a bucket has ACL rules that grant public access."

  event_pattern = <<PATTERN
{
  "source": [
    "aws.s3"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "s3.amazonaws.com"
    ],
    "eventName": [
      "PutBucketAcl",
      "CreateBucket"
    ]
  }
}
PATTERN

  function_name   = "S3BucketAclPublicAccess"
  source_code_dir = "${path.module}/source"
  handler         = "reflex_aws_s3_bucket_acl_public_access.lambda_handler"
  lambda_runtime  = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn,
    
  }


  queue_name    = "S3BucketAclPublicAccess"
  delay_seconds = 0

  target_id = "S3BucketAclPublicAccess"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}