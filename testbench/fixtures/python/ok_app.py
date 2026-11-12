import subprocess, hashlib
def run(args: list[str]):
    subprocess.run(["echo", *args], check=False)
def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
