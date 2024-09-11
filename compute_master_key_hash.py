import hashlib
import os

def compute_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

path = os.path.join(os.getcwd(),"MASTERKEY.txt")

hash_path = os.path.join(os.getcwd(),"MASTERKEYHASH.txt")
with open(hash_path,"w") as file:
    file.write(compute_file_hash(path))