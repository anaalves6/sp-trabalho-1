import os
import hashlib
import timeit
import statistics
from cryptography.hazmat.primitives.asymmetric import rsa
import matplotlib.pyplot as plt

# função auxiliar
def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def int_to_bytes(n, length):
    return n.to_bytes(length, byteorder='big')

# chaves RSA
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

MOD_BYTES = (public_key.public_numbers().n.bit_length() + 7) // 8

# funções RSA
def rsa_encrypt(r):
    r_int = bytes_to_int(r)
    c_int = pow(r_int, public_key.public_numbers().e, public_key.public_numbers().n)
    return int_to_bytes(c_int, MOD_BYTES)

def rsa_decrypt(c):
    c_int = bytes_to_int(c)
    r_int = pow(c_int, private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
    return int_to_bytes(r_int, 32)

# encriptação e decriptação
def encrypt_file(filename, r):
    with open(filename, "rb") as f:
        m = f.read()

    block_size = 32
    encrypted_blocks = []

    # RSA(r)
    rsa_r = rsa_encrypt(r)

    for i in range((len(m) + block_size - 1) // block_size):
        block = m[i*block_size:(i+1)*block_size]

        hasher = hashlib.sha256()
        hasher.update(i.to_bytes(4, 'big') + r)
        hash_block = hasher.digest()

        cipher_block = bytes(a ^ b for a, b in zip(block, hash_block[:len(block)]))
        encrypted_blocks.append(cipher_block)

    return rsa_r, encrypted_blocks

def decrypt_file(rsa_r, encrypted_blocks):
    # recuperar r com a chave privada
    r = rsa_decrypt(rsa_r)

    decrypted = bytearray()

    for i, cipher_block in enumerate(encrypted_blocks):
        hasher = hashlib.sha256()
        hasher.update(i.to_bytes(4, 'big') + r)
        hash_block = hasher.digest()

        plain_block = bytes(a ^ b for a, b in zip(cipher_block, hash_block[:len(cipher_block)]))
        decrypted.extend(plain_block)

    return decrypted

sizes = [8,64,512,4096,32768,262144,2097152]

encrypt_mean_list = []
encrypt_std_list = []
decrypt_mean_list = []
decrypt_std_list = []

repeats = 30

for size in sizes:
    filename = f"text_files/ficheiro_{size}.txt"

    # gerar novo r para cada ficheiro
    r = os.urandom(32)

    # encriptar uma vez para obter blocos
    rsa_r, enc_blocks = encrypt_file(filename, r)

    #medir encriptação
    encrypt_times = timeit.repeat(lambda: encrypt_file(filename, r), repeat=repeats, number=1)
    encrypt_times_us = [t*1e6 for t in encrypt_times]

    decrypt_times = timeit.repeat(lambda: decrypt_file(rsa_r, enc_blocks), repeat=repeats, number=1)
    decrypt_times_us = [t*1e6 for t in decrypt_times]

    #verificação
    with open(filename, "rb") as f:
        original = f.read()
    decrypted = decrypt_file(rsa_r, enc_blocks)
    assert decrypted == original, "Erro!"

    encrypt_mean_list.append(statistics.mean(encrypt_times_us))
    encrypt_std_list.append(statistics.stdev(encrypt_times_us))
    decrypt_mean_list.append(statistics.mean(decrypt_times_us))
    decrypt_std_list.append(statistics.stdev(decrypt_times_us))

def run_rsa():
    return sizes, encrypt_mean_list, encrypt_std_list, decrypt_mean_list, decrypt_std_list

# função para desenhar o gráfico
def plot_rsa():
    plt.figure(figsize=(10,6))

    # plot com barras de erro
    plt.errorbar(sizes, encrypt_mean_list, yerr=encrypt_std_list,
                marker='o', linestyle='-', label="Encryption")

    plt.errorbar(sizes, decrypt_mean_list, yerr=decrypt_std_list,
                marker='o', linestyle='-', label="Decryption")

    # escala log no eixo X
    plt.xscale("log")
    plt.xticks(sizes, sizes)

    # adicionar valores acima dos pontos
    for x, y in zip(sizes, encrypt_mean_list):
        plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

    for x, y in zip(sizes, decrypt_mean_list):
        plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

    plt.xlabel("File size (bytes)")
    plt.ylabel("Time (microseconds)")
    plt.title("RSA performance")
    plt.legend()
    plt.grid(True, which="both", linestyle='--', alpha=0.6)

    plt.savefig("plots/rsa_performance.png", dpi=300)
    plt.show()

run_rsa()
plot_rsa()