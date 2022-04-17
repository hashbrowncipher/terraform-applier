from subprocess import check_call
from resource import getrusage
from resource import RUSAGE_CHILDREN
import os
import shutil

if os.path.exists("/tmp/code"):
    shutil.rmtree("/tmp/code")

env = dict(os.environ)
env["HOME"] = "/tmp/code"
#env["TF_LOG"] = "TRACE"
shutil.copytree("/code", "/tmp/code", symlinks=True)
os.chdir("/tmp/code")
check_call(["terraform", "init"], env=env)
print(getrusage(RUSAGE_CHILDREN))

def handler(event, context):
    check_call(["terraform", "apply", "-auto-approve"], env=env)
    print(getrusage(RUSAGE_CHILDREN))
