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
from rdklib import Evaluation, ComplianceType, InvalidParametersError
import rdklibtest

RESOURCE_TYPE = 'AWS::S3::Bucket'

MODULE = __import__('S3_DEFAULT_ENCRYPTION_KMS')
RULE = MODULE.S3_DEFAULT_ENCRYPTION_KMS()

class ComplianceTest(unittest.TestCase):

    def test_scenario1_evaluateparameters_emptyruleparameter_returnsuccess(self):
        rule_invalid_parameter = {
            "KmsKeyArns":  ""
        }
        response = RULE.evaluate_parameters(rule_invalid_parameter)
        self.assertEqual(response, {})

    def test_scenario1_evaluateparameters_invalidruleparameter_returnserror(self):
        rule_invalid_parameter = {
            "KmsKeyArns":  "dummy-arn,arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
        }
        with self.assertRaises(InvalidParametersError) as context:
            RULE.evaluate_parameters(rule_invalid_parameter)
        self.assertIn('Invalid AWS KMS Key Arn format for "dummy-arn". AWS KMS Key Arn starts with "arn:aws:kms:"', str(context.exception))

    def test_scenario1_evaluateparameters_validruleparameter_returnsuccess(self):
        rule_valid_parameter = {
            "KmsKeyArns":  "  arn:aws:kms:us-west-2:123456789000:key/a3175963-d26f-4601-80d5-1959c9347f78,  arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
        }

        resp_expected = {
            "KmsKeyArns": [
                "arn:aws:kms:us-west-2:123456789000:key/a3175963-d26f-4601-80d5-1959c9347f78",
                "arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
            ]
        }

        response = RULE.evaluate_parameters(rule_valid_parameter)
        self.assertEqual(response, resp_expected)

    def test_scenario1_evaluateparameters_noruleparameter_returnsuccess(self):
        response = RULE.evaluate_parameters({})
        self.assertEqual(response, {})

    def test_scenario2_bucketencryptedwithkmskey_validruleparameter_returncompliant(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:us-west-2:123456789000:key/a3175963-d26f-4601-80d5-1959c9347f78",
                "arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
            ]
        }
        config_item = {
            "configuration": {
                "name": "dummy-s3-bucket-name"
            },
            "supplementaryConfiguration": {
                "ServerSideEncryptionConfiguration": {
                    "rules": [
                        {
                            "applyServerSideEncryptionByDefault": {
                                "sseAlgorithm": "aws:kms",
                                "kmsMasterKeyID": "arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
                            }
                        }
                    ]
                }
            }
        }

        response = RULE.evaluate_change({}, {}, config_item, valid_rule_parameter)
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_scenario3_bucketencryptedwithkmskey_noruleparameter_returncompliant(self):
        config_item = {
            "configuration": {
                "name": "dummy-s3-bucket-name"
            },
            "supplementaryConfiguration": {
                "ServerSideEncryptionConfiguration": {
                    "rules": [
                        {
                            "applyServerSideEncryptionByDefault": {
                                "sseAlgorithm": "aws:kms",
                                "kmsMasterKeyID": "arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
                            }
                        }
                    ]
                }
            }
        }
        response = RULE.evaluate_change({}, {}, config_item, {})
        resp_expected = [
            Evaluation(ComplianceType.COMPLIANT)
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_scenario4_bucketencryptedwithinvalidkmskey_validruleparameter_returnnoncompliant(self):
        valid_rule_parameter = {
            "KmsKeyArns": [
                "arn:aws:kms:us-west-2:123456789000:key/a3175963-d26f-4601-80d5-1959c9347f78",
                "arn:aws:kms:us-west-2:123456789000:key/32131231-53434-5342-80d5-112137654365"
            ]
        }
        config_item = {
            "configuration": {
                "name": "dummy-s3-bucket-name"
            },
            "supplementaryConfiguration": {
                "ServerSideEncryptionConfiguration": {
                    "rules": [
                        {
                            "applyServerSideEncryptionByDefault": {
                                "sseAlgorithm": "aws:kms",
                                "kmsMasterKeyID": "arn:aws:kms:us-west-2:123456789000:key/dummy-key"
                            }
                        }
                    ]
                }
            }
        }

        response = RULE.evaluate_change({}, {}, config_item, valid_rule_parameter)
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, annotation="AWS KMS key 'arn:aws:kms:us-west-2:123456789000:key/dummy-key' used to encrypt the Amazon S3 bucket is not in rule_paramter 'KmsKeyArns'")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_scenario5_bucketencryptedwithaes256_noruleparameter_returnnoncompliant(self):
        config_item = {
            "configuration": {
                "name": "dummy-s3-bucket-name"
            },
            "supplementaryConfiguration": {
                "ServerSideEncryptionConfiguration": {
                    "rules": [
                        {
                            "applyServerSideEncryptionByDefault": {
                                "sseAlgorithm": "AES256",
                                "kmsMasterKeyID": None
                            }
                        }
                    ]
                }
            }
        }

        response = RULE.evaluate_change({}, {}, config_item, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon S3 bucket is not encrypted with AWS KMS key")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)

    def test_scenario5_bucketnotencrypted_noruleparameter_returnnoncompliant(self):
        config_item = {
            "configuration": {
                "name": "dummy-s3-bucket-name"
            },
            "supplementaryConfiguration": {
            }
        }

        response = RULE.evaluate_change({}, {}, config_item, {})
        resp_expected = [
            Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon S3 bucket is not encrypted with AWS KMS key")
        ]
        rdklibtest.assert_successful_evaluation(self, response, resp_expected)
