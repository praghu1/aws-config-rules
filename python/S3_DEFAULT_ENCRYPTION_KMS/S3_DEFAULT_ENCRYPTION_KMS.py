'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
  S3_DEFAULT_ENCRYPTION_KMS

Description:
  Checks whether the Amazon S3 buckets are encrypted with AWS Key Management Service(AWS KMS). The rule is not NON_COMPLIANT if the Amazon S3 bucket is not encrypted with AWS KMS key.

Rationale:
  Encryption using AWS KMS protects the data at rest within Amazon S3.

Indicative Severity:
  High

Trigger:
  Configuration Change on AWS::S3::Bucket

Reports on:
  AWS::S3::Bucket

Rule Parameters:
  KmsKeyArns
    (Optional) Comma separated list of AWS KMS key ARNs allowed for encrypting Amazon S3 Buckets.

Scenarios:
  Scenario: 1
     Given: Rules parameter is provided
       And: Any key in "KmsKeyArns" is invalid
      Then: Return ERROR

  Scenario: 2
     Given: Rules parameter is provided
       And: Amazon S3 Bucket is encrypted using SSE-KMS
       And: 'kmsMasterKeyID' is in KmsArn list
      Then: Return COMPLIANT

  Scenario: 3
     Given: Amazon S3 Bucket is encrypted using SSE-KMS
      Then: Return COMPLIANT

  Scenario: 4
    Given: Rules parameter is provided
      And: Amazon S3 Bucket is encrypted using SSE-KMS
      And: 'kmsMasterKeyID' is not in KmsArn list
     Then: Return NON_COMPLIANT with annotation 'S3 bucket is not encrypted with KMS key provided in the rule parameter "KmsKeyArns"'

  Scenario: 5
     Given: Amazon S3 Bucket is not encrypted using SSE-KMS
      Then: Return NON_COMPLIANT with annotation 'Amazon S3 bucket is not encrypted with AWS KMS key'
'''

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType, InvalidParametersError

RESOURCE_TYPE = "AWS::S3::Bucket"
class S3_DEFAULT_ENCRYPTION_KMS(ConfigRule):

    def evaluate_change(self, event, client_factory, configuration_item, valid_rule_parameters):
        s3_encryption_configuration = configuration_item['supplementaryConfiguration'].get('ServerSideEncryptionConfiguration')

        if s3_encryption_configuration:
            sse_algorithm = s3_encryption_configuration['rules'][0]['applyServerSideEncryptionByDefault']['sseAlgorithm']
            kms_master_key_id = s3_encryption_configuration['rules'][0]['applyServerSideEncryptionByDefault']['kmsMasterKeyID']
            kms_arn_list = valid_rule_parameters.get("KmsKeyArns")

            if sse_algorithm == 'aws:kms':
                if not kms_arn_list:
                    return [Evaluation(ComplianceType.COMPLIANT)]
                if kms_master_key_id in kms_arn_list:
                    return [Evaluation(ComplianceType.COMPLIANT)]
                return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="AWS KMS key '{}' used to encrypt the Amazon S3 bucket is not in rule_paramter 'KmsKeyArns'".format(kms_master_key_id))]

        return [Evaluation(ComplianceType.NON_COMPLIANT, annotation="Amazon S3 bucket is not encrypted with AWS KMS key")]

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = {}
        if 'KmsKeyArns' in rule_parameters:
            kms_key_arns = "".join(rule_parameters['KmsKeyArns'].split())
            if kms_key_arns:
                kms_key_arns = kms_key_arns.split(',')
                for kms_key_arn in kms_key_arns:
                    if not kms_key_arn.startswith('arn:aws:kms:'):
                        raise InvalidParametersError('Invalid AWS KMS Key Arn format for "{}". AWS KMS Key Arn starts with "arn:aws:kms:"'.format(kms_key_arn))
                valid_rule_parameters['KmsKeyArns'] = kms_key_arns
        return valid_rule_parameters

def lambda_handler(event, context):
    my_rule = S3_DEFAULT_ENCRYPTION_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
