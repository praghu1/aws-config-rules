'''
#####################################
##           Gherkin               ##
#####################################
Rule Name:
S3_BUCKET_ENCRYPTED_KMS

Description:
Check whether Amazon S3 bucket is encrypted with KMS key.

Rationale:
Ensure that the Amazon S3 bucket is always encrypted with the KMS key so that no clear text documents.

Indicative Severity:
High

Trigger:
Periodic

Reports on:
AWS::S3::Bucket

Rule Parameters:
None

Scenarios:
Scenario: 1
  Given: There is no S3 Bucket
   Then: Return NOT_APPLICABLE
Scenario: 2
  Given: S3 Bucket is encrypted with AWS-KMS
   Then: Return COMPLIANT
Scenario: 3
  Given: S3 Bucket is not encrypted
   Then: Return NON_COMPLIANT
Scenario: 4
  Given: S3 Bucket is encrypted with Amazon S3 server side encryption(AES-256)
   Then: Return NON_COMPLIANT
'''

from rdklib import Evaluator, Evaluation, ConfigRule, ComplianceType

RESOURCE_TYPE = "AWS::S3::Bucket"
class S3_BUCKET_ENCRYPTED_KMS(ConfigRule):

    def evaluate_periodic(self, event, client_factory, valid_rule_parameters):
        evaluations = []

        s3_client = client_factory.build_client('s3')
        response = s3_client.list_buckets()

        if len(response['Buckets']) == 0:
            return [Evaluation(ComplianceType.NOT_APPLICABLE)]

        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            evaluations.append(is_s3_bucket_kms_encrypted(s3_client, bucket_name))

        return evaluations

    def evaluate_parameters(self, rule_parameters):
        valid_rule_parameters = rule_parameters
        return valid_rule_parameters


def is_s3_bucket_kms_encrypted(s3_client, bucket_name):
    try:
        response = s3_client.get_bucket_encryption(Bucket=bucket_name)
        algorithm = response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        if algorithm == 'aws:kms':
            return Evaluation(ComplianceType.COMPLIANT, bucket_name, RESOURCE_TYPE)

        return Evaluation(ComplianceType.NON_COMPLIANT, bucket_name, RESOURCE_TYPE, "Not encrypted with KMS key")
    except:
        return Evaluation(ComplianceType.NON_COMPLIANT, bucket_name, RESOURCE_TYPE, "Not encrypted with KMS key")

################################
# DO NOT MODIFY ANYTHING BELOW #
################################
def lambda_handler(event, context):
    my_rule = S3_BUCKET_ENCRYPTED_KMS()
    evaluator = Evaluator(my_rule)
    return evaluator.handle(event, context)
