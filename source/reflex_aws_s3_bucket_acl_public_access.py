""" Module for S3BucketAclPublicAccess """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation


class S3BucketAclPublicAccess(AWSRule):
    """ Detect when a bucket has ACL rules that grant public access. """

    def __init__(self, event):
        super().__init__(event)
        self.public_group_uris = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ]

    def extract_event_data(self, event):
        """ Extract required event data """
        self.bucket_name = event["detail"]["requestParameters"]["bucketName"]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        return not self.bucket_has_public_access_acl(self.bucket_name)

    def bucket_has_public_access_acl(self, bucket):
        """Determines if the specified bucket has an ACL that provides public access.

        Args:
            bucket (string): S3 bucket name

        Returns:
            bool: True if ACL provides public access. False otherwise.
        """
        response = self.client.get_bucket_acl(Bucket=bucket)
        grants = response["Grants"]

        for grant in grants:
            if grant["Grantee"]["URI"] in self.public_group_uris:
                return True

        return False

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return (
            f"The S3 bucket {self.bucket_name} contains an ACL that "
            f"grants Public Access "
        )


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    rule = S3BucketAclPublicAccess(event_payload)
    rule.run_compliance_rule()
