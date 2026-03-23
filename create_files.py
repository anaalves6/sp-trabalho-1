import os

sizes = [8,64,512,4096,32768,262144,2097152]

for x in sizes:
    with open (f"ficheiro_{x}.txt", "wb") as f:
        f.write(os.urandom(x))