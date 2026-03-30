import os
import statistics
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import timeit

# tamanhos dos ficheiros
sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]

# chave AES e nonce fixo
key = os.urandom(32)
nonce = os.urandom(16)

# funções de encriptação e decriptação
def aes_encrypt(data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# listas para guardar os tempos médios
aes_enc = []
aes_dec = []

aes_encstd = []
aes_decstd = []

# listas para guardar os tempos de encriptação e decriptação do ficheiro maior
enc_2097152_runs = []
dec_2097152_runs = []

# número de repetições
repeats = 30

for s in sizes:
    with open(f"text_files/ficheiro_{s}.txt", "rb") as f:
        data = f.read()

    enc_func = lambda: aes_encrypt(data)
    ciphertext = aes_encrypt(data)
    dec_func = lambda: aes_decrypt(ciphertext)

    # timeit.repeat para medir múltiplas vezes
    enc_times = timeit.repeat(enc_func, repeat=repeats, number=1)
    dec_times = timeit.repeat(dec_func, repeat=repeats, number=1)

    # converter para microsegundos
    enc_times_us = [t * 1e6 for t in enc_times]
    dec_times_us = [t * 1e6 for t in dec_times]

    # parte para guardar os tempos de execução
    if s == 2097152:
        enc_2097152_runs = enc_times_us[:15]
        dec_2097152_runs = dec_times_us[:15]

    # calcular média e desvio padrão
    enc_mean = statistics.mean(enc_times_us)
    enc_std = statistics.stdev(enc_times_us)

    dec_mean = statistics.mean(dec_times_us)
    dec_std = statistics.stdev(dec_times_us)

    # guarda nas listas para o gráfico
    aes_enc.append(enc_mean)
    aes_dec.append(dec_mean)

    aes_encstd.append(enc_std)
    aes_decstd.append(dec_std)

def run_aes():
    return sizes, aes_enc, aes_encstd, aes_dec, aes_decstd

# função para desenhar o gráfico
def plot_aes():
    plt.figure(figsize=(10,6))

    # plot com barras de erro
    plt.errorbar(sizes, aes_enc, yerr=aes_encstd, marker='o', linestyle='-', label="Encryption")
    plt.errorbar(sizes, aes_dec, yerr=aes_decstd, marker='o', linestyle='-', label="Decryption")

    # escala log no eixo X
    plt.xscale("log")
    plt.xticks(sizes, sizes)  # marca explicitamente os 7 tamanhos

    # adicionar valores acima dos pontos
    for x, y in zip(sizes, aes_enc):
        plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)
    for x, y in zip(sizes, aes_dec):
        plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

    plt.xlabel("File size (bytes)")
    plt.ylabel("Time (microseconds)")
    plt.title("AES Performance")
    plt.legend()
    plt.grid(True, which="both", linestyle='--', alpha=0.6)

    plt.savefig("plots/aes_performance.png", dpi=300)
    plt.show()

# função que desenha o gráfico dos diferentes tempo de encriptação e decriptação 
def plot_first_15_runs():
    runs = list(range(1, 16))

    plt.figure(figsize=(10,6))

    plt.plot(runs, enc_2097152_runs, marker='o', linestyle='-', label="Encryption")
    plt.plot(runs, dec_2097152_runs, marker='o', linestyle='-', label="Decryption")

    plt.xlabel("Run number")
    plt.ylabel("Time (microseconds)")
    plt.title("AES Execution Time (First 15 Runs, File Size = 2097152 bytes)")
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.6)

    plt.savefig("plots/aes_2097152_first15.png", dpi=300)
    plt.show()
