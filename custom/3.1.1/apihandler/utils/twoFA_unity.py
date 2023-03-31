import os
import subprocess


def delete_user_2fa(username):
    priv_key = os.environ.get("TWOFA_REMOVE_SSH_KEY", None)
    user = os.environ.get("TWOFA_REMOVE_SSH_USER", None)
    host = os.environ.get("TWOFA_REMOVE_SSH_HOST", None)
    if not priv_key:
        raise Exception("Please define TWOFA_REMOVE_SSH_KEY environment variable")
    if not user:
        raise Exception("Please define TWOFA_REMOVE_SSH_USER environment variable")
    if not host:
        raise Exception("Please define TWOFA_REMOVE_SSH_HOST environment variable")
    cmd = [
        "ssh",
        "-i",
        priv_key,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{user}@{host}",
        f"UID={username}",
    ]
    subprocess.Popen(cmd)


def add_user_2fa(username):
    priv_key = os.environ.get("TWOFA_SSH_KEY", None)
    user = os.environ.get("TWOFA_SSH_USER", None)
    host = os.environ.get("TWOFA_SSH_HOST", None)
    if not priv_key:
        raise Exception("Please define TWOFA_SSH_KEY environment variable")
    if not user:
        raise Exception("Please define TWOFA_SSH_USER environment variable")
    if not host:
        raise Exception("Please define TWOFA_SSH_HOST environment variable")
    cmd = [
        "ssh",
        "-i",
        priv_key,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        f"{user}@{host}",
        f"UID={username}",
    ]
    subprocess.Popen(cmd)
