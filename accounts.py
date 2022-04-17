#!/usr/bin/env python3
from base64 import b64decode
from boto3 import client
from subprocess import check_call
from subprocess import check_output
from subprocess import run
from typing import Optional
from dataclasses import dataclass
from dataclasses import field
from time import sleep
from uuid import uuid4
import json
import yaml

from aws import assumed_role_session
from aws import get_s3_bucket_tags
from aws import IAMPolicy
from terraform import Code
from terraform import Interpolated
from terraform import NoOverwriteDict


def _allow_lambda():
    arp = IAMPolicy()
    arp.allow("sts:AssumeRole", principal=dict(Service="lambda.amazonaws.com"))
    return arp.serialize()


ALLOW_LAMBDA_POLICY = _allow_lambda()

interpolate = Interpolated.format


@dataclass(frozen=True)
class Account:
    name: str
    email: str
    terraform: bool

    def _generate_iam_policy(self, bucket, account_id):
        policy = IAMPolicy()
        policy.allow(
            ["s3:GetObject", "s3:PutObject"],
            interpolate("arn:aws:s3:::{}/{}/*", bucket, account_id),
        )

        policy.allow(
            "sts:AssumeRole",
            interpolate(
                "arn:aws:iam::{}:role/terraform_root", account_id
            ),
        )

        return dict(name="policy", policy=policy.serialize())

    def _set_up_terraform(self, code, state_bucket, account_id):
        if not self.terraform:
            return

        policy = self._generate_iam_policy(state_bucket, account_id)
        role = code.add_resource(
            "aws_iam_role",
            "terraform_" + self.name,
            name=self.name,
            path="/terraform/",
            assume_role_policy=ALLOW_LAMBDA_POLICY,
            managed_policy_arns=[],
            inline_policy=[policy],
        )

        code.add_resource(
            "aws_ecr_repository",
            "terraform_" + self.name,
            name=interpolate("terraform/{}", account_id),
        )

    def add_to(self, code, state_bucket):
        account = code.add_resource(
            "aws_organizations_account",
            self.name,
            name=self.name,
            email=self.email,
            provider="aws.assumed",
        )
        self._set_up_terraform(code, state_bucket, account.suffixed("id"))

    @classmethod
    def create(cls, email_template, name, config):
        config = NoOverwriteDict(config)
        config["name"] = name
        config["email"] = email_template.format(**config)

        return cls(**config)


def _make_ecr_repository(ecr):
    try:
        repos = ecr.describe_repositories(repositoryNames=["terraform/root"])
    except ecr.exceptions.RepositoryNotFoundException:
        pass
    else:
        return repos["repositories"][0]["repositoryUri"]

    return ecr.create_repository(repositoryName="terraform/root")["repository"][
        "repositoryUri"
    ]


def _make_ecr_resources(ecr):
    resp = ecr.get_authorization_token()
    auth_data = resp["authorizationData"][0]
    user, password = b64decode(auth_data["authorizationToken"].encode()).split(b":")

    return {
        "user": user.decode(),
        "password": password,
        "login_at": auth_data["proxyEndpoint"],
        "uri": _make_ecr_repository(ecr),
    }


def _create_separate_account(name, email_template):
    organizations = client("organizations")

    # TODO: don't always pick the first?
    root_ou = organizations.list_roots()["Roots"][0]["Id"]

    for account in organizations.list_accounts_for_parent(ParentId=root_ou)["Accounts"]:
        if account["Name"] == name:
            return account["Id"]

    response = organizations.create_account(
        AccountName=name, Email=email_template.format(name=name)
    )
    status = response["CreateAccountStatus"]
    request_id = status["Id"]

    while status["State"] == "IN_PROGRESS":
        sleep(5)
        status = organizations.describe_create_account_status(
            CreateAccountRequestId=request_id,
        )["CreateAccountStatus"]

    if status["State"] == "SUCCEEDED":
        return status["AccountId"]

    raise RuntimeError("Account creation failed", status)


def _create_s3_bucket(s3, region):
    buckets = s3.list_buckets()["Buckets"]
    for bucket in buckets:
        if not bucket["Name"].startswith("terraform-"):
            continue

        tags = get_s3_bucket_tags(s3, bucket["Name"])

        if tags is None:
            continue

        if tags.get("LocalName") == "terraform":
            return bucket["Name"]

    bucket_name = "terraform-" + str(uuid4())
    s3.create_bucket(
        Bucket=bucket_name,
        CreateBucketConfiguration=dict(
            LocationConstraint=region,
        ),
    )
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration=dict(
            Rules=[
                dict(
                    ApplyServerSideEncryptionByDefault=dict(SSEAlgorithm="AES256"),
                    BucketKeyEnabled=True,
                )
            ]
        ),
    )
    s3.put_bucket_versioning(
        Bucket=bucket_name, VersioningConfiguration=dict(Status="Enabled")
    )
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration=dict(
            BlockPublicAcls=True,
            IgnorePublicAcls=True,
            BlockPublicPolicy=True,
            RestrictPublicBuckets=True,
        ),
    )
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging=dict(TagSet=[dict(Key="LocalName", Value="terraform")]),
    )

    return bucket_name


def _create_lambda_role(iam, region_name, management_role_arn, account_id, bucket, lambda_name):
    policy = IAMPolicy()
    policy.allow(
        ["s3:GetObject", "s3:PutObject"],
        f"arn:aws:s3:::{bucket}/root/*",
    )

    # this is something to do with tf workspaces that I don't understand
    policy.allow(
        ["s3:ListBucket"],
        f"arn:aws:s3:::{bucket}",
        condition=dict(StringEquals={"s3:prefix": [
            "env:/",
        ]})
    )

    policy.allow(
        ["s3:ListBucket"],
        f"arn:aws:s3:::{bucket}",
        condition=dict(StringLike={"s3:prefix": [
            "root/*",
        ]})
    )

    policy.allow(
        ["dynamodb:*"],
        f"arn:aws:dynamodb:{region_name}:{account_id}:table/terraform-locks",
        condition={
            "ForAllValues:StringLike": {"dynamodb:LeadingKeys": [f"{bucket}/root/*"]}
        },
    )

    log_group_arn = (
        f"arn:aws:logs:{region_name}:{account_id}:log-group:/aws/lambda/" + lambda_name
    )

    policy.allow(
        ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
        [log_group_arn, log_group_arn + ":log-stream:*"],
    )


    policy.allow("sts:AssumeRole", management_role_arn)

    create_role_with_policy(
        iam, "lambda_" + lambda_name, policy, ALLOW_LAMBDA_POLICY, "Terraform account"
    )


def _create_management_role(terraform_role):
    account_id = client("sts").get_caller_identity()["Account"]
    policy = IAMPolicy()
    policy.allow("*", "*")

    arp = IAMPolicy()
    arp.allow("sts:AssumeRole", principal=dict(AWS=terraform_role))

    create_role_with_policy(
        client("iam"),
        "terraform_root",
        policy,
        arp.serialize_direct(),
        "management account",
    )

    return f"arn:aws:iam::{account_id}:role/terraform_root"


def initialize(region, email_template):
    lambda_name = "terraform"
    account_id = _create_separate_account("terraform4", email_template)

    terraform_role_arn = f"arn:aws:iam::{account_id}:role/lambda_{lambda_name}"
    management_role_arn = _create_management_role(terraform_role_arn)

    control_plane = assumed_role_session(
        client("sts", region_name=region),
        region,
        dict(
            RoleArn=f"arn:aws:iam::{account_id}:role/OrganizationAccountAccessRole",
            RoleSessionName="terraform",
        ),
    )

    iam = control_plane.client("iam")
    s3 = control_plane.client("s3")
    dynamodb = control_plane.client("dynamodb")

    bucket = _create_s3_bucket(s3, region)
    role = _create_lambda_role(iam, region, management_role_arn, account_id, bucket, lambda_name)

    try:
        dynamodb.create_table(
            TableName="terraform-locks",
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                dict(
                    AttributeName="LockID",
                    AttributeType="S",
                ),
            ],
            KeySchema=[dict(AttributeName="LockID", KeyType="HASH")],
        )
    except dynamodb.exceptions.ResourceInUseException:
        pass

    ecr = control_plane.client("ecr")

    return dict(
        management_role=management_role_arn,
        control_plane=control_plane,
        bucket=bucket,
        ecr=_make_ecr_resources(ecr),
        role_arn=role,
        lambda_name=lambda_name,
    )


def _get_accounts(email_template, accounts):
    ret = []
    for name, config in accounts.items():
        ret.append(Account.create(email_template, name, config))

    return ret


def _create_function(control_plane, role_arn, digest, name):
    print(role_arn)
    lamda = control_plane.client("lambda")
    function = None
    try:
        function = lamda.get_function(FunctionName=name)
    except lamda.exceptions.ResourceNotFoundException:
        pass

    if function is None:
        lamda.create_function(
            FunctionName=name,
            Role=role_arn,
            Code=dict(ImageUri=digest),
            Timeout=900,
            PackageType="Image",
            MemorySize=512,
        )
    else:
        image_uri = function["Code"]["ImageUri"]
        if image_uri == digest:
            print("No changes to lambda")
            return lamda

        lamda.update_function_code(
            FunctionName=name,
            ImageUri=digest,
        )
        print("Waiting for function update")

    waiter = lamda.get_waiter("function_updated_v2")
    waiter.wait(FunctionName=name)

    return lamda


def docker_build_and_push(ecr_resources):
    repository_uri = ecr_resources["uri"]

    run(
        [
            "docker",
            "login",
            "--username",
            ecr_resources["user"],
            "--password-stdin",
            ecr_resources["login_at"],
        ],
        input=ecr_resources["password"],
        check=True,
    )
    check_call(["docker", "build", "-t", f"{repository_uri}:latest", "docker"])
    check_call(["docker", "push", f"{repository_uri}:latest"])

    # Apparently RepoDigests are a thing separate from image IDs? TIL
    return json.loads(
        check_output(["docker", "inspect", f"{repository_uri}:latest"]).decode()
    )[0]["RepoDigests"][0]


def main():
    with open("config.yaml", "r") as config_fh:
        config = yaml.safe_load(config_fh)

    accounts = _get_accounts(config["email_template"], config["accounts"])
    region = config["region"]
    resources = initialize(region, config["email_template"])

    code = Code()
    terraform = code.child("terraform")
    backend = terraform.child("backend")
    terraform.child("required_providers")["aws"] = dict(
        source="hashicorp/aws",
        version="~> 4.0",
    )

    code.child("provider")["aws"] = [
        dict(region=region),
        dict(
            alias="assumed",
            region=region,
            assume_role=dict(
                role_arn=resources["management_role"]
            ),
        )
    ]

    backend["s3"] = dict(
        bucket=resources["bucket"],
        key="root/tfstate",
        region=region,
        dynamodb_table="terraform-locks",
    )

    for account in accounts:
        account.add_to(code, resources["bucket"])

    with open("docker/code/output.tf.json", "w") as fh:
        code.write(fh)

    digest = docker_build_and_push(resources["ecr"])
    lamda = _create_function(
        resources["control_plane"],
        resources["role_arn"], 
        digest,
        resources["lambda_name"]
    )
    print("Executing function")
    response = lamda.invoke(FunctionName=resources["lambda_name"])
    print(response)


def create_role_with_policy(iam, name, policy, arp, account_description):
    for i in range(2):
        try:
            print(f"Putting role policy for '{name}' in {account_description}")
            iam.put_role_policy(
                RoleName=name,
                PolicyName="policy",
                PolicyDocument=policy.serialize_direct(),
            )
        except iam.exceptions.NoSuchEntityException:
            print(f"Role '{name}' in {account_description} doesn't exist yet")
            if i > 0:
                raise
        else:
            break

        print(f"Creating role '{name}' in {account_description}")
        role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=arp)


if __name__ == "__main__":
    raise SystemExit(main())
