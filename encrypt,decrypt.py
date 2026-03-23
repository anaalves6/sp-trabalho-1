import os
import time
import statistics
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

sizes = [8,64,512,4096,32768,262144,2097152]

key = os.urandom(32)
#escrever no relatório que decidimos criar um nonce fixo por não estarmos preocupadas com segurança mas sim com o tempo de execução do AES
nonce = os.urandom(16)

def aes_encrypt(data):

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()

    return encryptor.update(data) + encryptor.finalize()


def aes_decrypt(ciphertext):

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


for s in sizes:

    with open(f"ficheiro_{s}.txt","rb") as f:
        data = f.read()

    enc_times=[]
    dec_times=[]

    for _ in range(30):

        start=time.perf_counter()
        c=aes_encrypt(data)
        enc_times.append(time.perf_counter()-start)

        start=time.perf_counter()
        aes_decrypt(c)
        dec_times.append(time.perf_counter()-start)

    enc_mean=statistics.mean(enc_times)*1e6
    enc_std=statistics.stdev(enc_times)*1e6

    dec_mean=statistics.mean(dec_times)*1e6
    dec_std=statistics.stdev(dec_times)*1e6

    print(
        s,
        "ENC:",enc_mean,"±",enc_std,
        "DEC:",dec_mean,"±",dec_std
    )


#explicar como sabemos que o que fizemos esta correto
#como fizemos benchmarking e explicar os resultados(comparar tamanhos e algoritmos)