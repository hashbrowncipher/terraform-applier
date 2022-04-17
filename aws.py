import json
from dataclasses import dataclass
from dataclasses import field
from typing import Union
from typing import Optional

from botocore.credentials import DeferredRefreshableCredentials
from botocore.credentials import create_assume_role_refresher
from botocore import session as botocore_session
import boto3

from terraform import Interpolated

def assumed_role_session(sts, region_name, params):
    refresh = create_assume_role_refresher(sts, params)
    credentials = DeferredRefreshableCredentials(method="assume-role", refresh_using=refresh)

    session = botocore_session.Session()
    session._credentials = credentials
    return boto3.Session(botocore_session=session, region_name=region_name)

def get_s3_bucket_tags(s3, name):
    try:
        tagging = s3.get_bucket_tagging(Bucket=name)
    except s3.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchTagSet":
            raise

        return None

    return {t["Key"]: t["Value"] for t in tagging["TagSet"]}


@dataclass(eq=True)
class IAMPolicy:
    _statements: list[dict] = field(default_factory=list)

    def allow(self, action: Union[str, list[str]], resource: Optional[str] = None, **kwargs):
        stmt = dict(Effect="Allow")
        if isinstance(action, str):
            action = [action]

        kwargs["action"] = action
        if resource is not None:
            kwargs["resource"] = resource

        for key, value in kwargs.items():
            key = key[0].upper() + key[1:]
            stmt[key] = value
        self._statements.append(stmt)

    def as_dict(self):
        return dict(
            Version="2012-10-17",
            Statement=self._statements,
        )

    def serialize_direct(self):
        return json.dumps(self.as_dict())

    def serialize(self):
        return Interpolated.jsonencode(self.as_dict())

