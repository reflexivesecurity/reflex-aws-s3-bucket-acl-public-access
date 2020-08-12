module "cwe" {
  source      = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe?ref=v2.0.0"
  name        = "S3BucketAclPublicAccess"
  description = "Detect when a bucket has ACL rules that grant public access."

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

}
