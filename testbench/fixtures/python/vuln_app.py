import os, subprocess, pickle, hashlib
def run(user):
    # intentional fixture: shell injection surface
    os.system("echo " + user)
    subprocess.run("ls " + user, shell=True)
def load(b):
    return pickle.loads(b)
def auth(pw):
    return hashlib.md5(pw.encode()).hexdigest()
