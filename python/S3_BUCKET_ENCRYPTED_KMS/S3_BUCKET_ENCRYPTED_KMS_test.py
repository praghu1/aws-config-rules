# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the License is located at
#
#        http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for
# the specific language governing permissions and limitations under the License.

import unittest
from mock import patch, MagicMock
from rdklib import Evaluation, ComplianceType
import rdklibtest

##############
# Parameters #
##############

# Define the default resource to report to Config Rules
RESOURCE_TYPE = 'AWS::S3::Bucket'

#############
# Main Code #
#############

MODULE = __import__('S3_BUCKET_ENCRYPTED_KMS')
RULE = MODULE.S3_BUCKET_ENCRYPTED_KMS()

CLIENT_FACTORY = MagicMock()

#example for mocking S3 API calls
S3_CLIENT_MOCK = MagicMock()

def mock_get_client(client_name, *args, **kwargs):
    if client_name == 's3':
        return S3_CLIENT_MOCK
    raise Exception("Attempting to create an unknown client")

@patch.object(CLIENT_FACTORY, 'build_client', MagicMock(side_effect=mock_get_client))
class ComplianceTest(unittest.TestCase):

    test1_list_bucket = {"Buckets":[{"Name":"test-bucket-name-1"}]}
    test1_encryption = {"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms", "KMSMasterKeyID":"dummy-key-id"}}]}}

    test2_list_bucket = {"Buckets":[{"Name":"test-bucket-name-2"}]}
    test2_encryption = {}

    test3_list_bucket = {"Buckets":[]}

    test4_list_bucket = {"Buckets":[{"Name":"test-bucket-name-4"}]}
    test4_encryption = {"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES"}}]}}

    def setUp(self):
        pass

    def test_compliant_bucket_compliant(self):
        S3_CLIENT_MOCK.list_buckets.return_value = self.test1_list_bucket
        S3_CLIENT_MOCK.get_bucket_encryption.return_value = self.test1_encryption
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT, 'test-bucket-name-1', RESOURCE_TYPE),
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, evaluations_count=1)

    def test_compliant_bucket_non_compliant(self):
        S3_CLIENT_MOCK.list_buckets.return_value = self.test2_list_bucket
        S3_CLIENT_MOCK.get_bucket_encryption.return_value = self.test2_encryption
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, 'test-bucket-name-2', RESOURCE_TYPE, "Not encrypted with KMS key"),
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, evaluations_count=1)

    def test_compliant_bucket_not_applicable(self):
        S3_CLIENT_MOCK.list_buckets.return_value = self.test3_list_bucket
        S3_CLIENT_MOCK.get_bucket_encryption.return_value = {}
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.NOT_APPLICABLE),
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, evaluations_count=1)

    def test_compliant_bucket_non_compliant_aes_encrypted(self):
        S3_CLIENT_MOCK.list_buckets.return_value = self.test4_list_bucket
        S3_CLIENT_MOCK.get_bucket_encryption.return_value = self.test4_encryption
        response = RULE.evaluate_periodic({}, CLIENT_FACTORY, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, 'test-bucket-name-4', RESOURCE_TYPE, "Not encrypted with KMS key"),
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected, evaluations_count=1)
