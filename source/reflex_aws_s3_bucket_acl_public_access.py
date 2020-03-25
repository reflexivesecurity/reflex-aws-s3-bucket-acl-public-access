""" Module for S3BucketAclPublicAccess """

import json
import os

import boto3
from reflex_core import AWSRule


class S3BucketAclPublicAccess(AWSRule):
    """ Detect when a bucket has ACL rules that grant public access. """

    # TODO: Instantiate whatever boto3 client you'll need, if any.

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        # TODO: Extract any data you need from the triggering event.
        self.event_name = event["detail"]["eventName"]
        self.bucket_name = event["detail"]["requestParameters"]["bucketName"]
        self.non_compliant_acl_list = ["public-read", "public-read-write"]

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        if self.event_name == "CreateBucket":
            return self.is_create_bucket()
        elif self.event_name == "PutBucketAcl":
            return self.is_put_bucket_acl()

    def is_create_bucket(self):
        if "x-amz-acl" in self.event["detail"]["requestParameters"].keys():
            for acl in self.event["detail"]["requestParameters"][
                    "x-amz-acl"]:
                if acl in self.non_compliant_acl_list:
                    return False
            return True
        return True

    def is_put_bucket_acl(self):
        if "x-amz-acl" in self.event["detail"]["requestParameters"].keys():
            for acl in self.event["detail"]["requestParameters"]["x-amz-acl"]:
                if acl in self.non_compliant_acl_list:
                    return False
            return True
        else:
            if isinstance(self.event["detail"]["requestParameters"][
                              "AccessControlPolicy"]["AccessControlList"][
                              "Grant"], list):
                for grant in self.event["detail"]["requestParameters"][
                        "AccessControlPolicy"]["AccessControlList"]["Grant"]:
                    if grant["Grantee"]["xsi:type"] == "Group":
                        return False
            if isinstance(self.event["detail"]["requestParameters"][
                              "AccessControlPolicy"]["AccessControlList"][
                              "Grant"], dict):
                grant = self.event["detail"]["requestParameters"][
                    "AccessControlPolicy"]["AccessControlList"]["Grant"]
                if grant["Grantee"]["xsi:type"] == "Group":
                    return False
                return True
            return True

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The S3 bucket {self.bucket_name} contains an ACL that " \
               f"grants Public Access "


def lambda_handler(event, _):
    """ Handles the incoming event """
    rule = S3BucketAclPublicAccess(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
