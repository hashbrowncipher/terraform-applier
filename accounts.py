import json
from boto3 import client
from subprocess import check_call
from subprocess import check_output

class NoOverwriteDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise KeyError(key)

        super().__setitem__(key, value)

    def child(self, key):
        try:
            return self[key]
        except KeyError:
            pass

        ret = type(self)()
        self[key] = ret
        return ret


class Code:
    def __init__(self):
        self._code = NoOverwriteDict()

    def child(self, path):
        return self._code.child(path)

    def add_resource(self, *args, **data):
        typ, name = args
        add_to = self._code.child("resource").child(typ)
        add_to[name] = data

    def write(self, fh):
        json.dump(self._code, fh, indent=2, sort_keys=True)

def initialize(region, bucket):
    s3 = client("s3", region_name=region)
    dynamodb = client("dynamodb", region_name=region)
    ecr = client('ecr', region_name=region)

    try:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration=dict(
            LocationConstraint=region,
        ))
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass

    try:
        repos = ecr.describe_repositories(repositoryNames=["terraform/root"])
    except ecr.exceptions.RepositoryNotFoundException:
        pass
    else:
        return repos["repositories"][0]["repositoryUri"]

    return ecr.create_repository(repositoryName="terraform/root")["repository"]["repositoryUri"]


def main():
    region = "us-west-2"
    state_bucket = "tfstate-3b0791ce-9aae-4efc-9fdb-b9f5bcb2abe0"
    repository_uri = initialize("us-west-2", state_bucket)

    code = Code()
    terraform = code.child("terraform")
    backend = terraform.child("backend")
    terraform.child("required_providers")["aws"] = dict(
        source = "hashicorp/aws",
        version = "~> 4.0",
    )

    code.child("provider")["aws"] = dict(region=region)

    backend["s3"] = dict(
        bucket=state_bucket,
        key="root",
        region="us-west-2",
    )

    code.add_resource(
        "aws_iam_role",
        "tf-account1",
        name="account1",
        path="/terraform/",
        assume_role_policy = json.dumps(dict(
            Version="2012-10-17",
            Statement=[
                dict(
                    Action="sts:AssumeRole",
                    Effect="Allow",
                    Principal=dict(Service="lambda.amazonaws.com")
                )
            ]
        ))
    )

    with open("docker/code/output.tf.json", "w") as fh:
        code.write(fh)

    check_call(["docker", "build", "-t", f"{repository_uri}:latest", "docker"])
    check_call(["docker", "push", f"{repository_uri}:latest"])

    # Apparently RepoDigests are a thing separate from image IDs? TIL
    digest = json.loads(check_output(["docker", "inspect", f"{repository_uri}:latest"]).decode())[0]["RepoDigests"][0]

    lamda = client("lambda", region_name=region)
    lamda.update_function_code(
        FunctionName="terraform",
        ImageUri=digest,
    )
    print("Waiting for function update")
    waiter = lamda.get_waiter("function_updated_v2")
    waiter.wait(FunctionName="terraform")


if __name__ == '__main__':
    raise SystemExit(main())
