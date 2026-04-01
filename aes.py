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

enc_diff_files_runs = []
dec_diff_files_runs = []

# número de repetições
repeats = 30

for s in sizes:
    with open(f"text_files/ficheiro_{s}.txt", "rb") as f:
        data = f.read()

    ciphertext = aes_encrypt(data)

    # timeit.repeat para medir múltiplas vezes
    enc_times = timeit.repeat(lambda: aes_encrypt(data), repeat=repeats, number=1)
    dec_times = timeit.repeat(lambda: aes_decrypt(ciphertext), repeat=repeats, number=1)

    # converter para microsegundos
    enc_times_us = [t * 1e6 for t in enc_times]
    dec_times_us = [t * 1e6 for t in dec_times]

    # parte para guardar os tempos de execução
    if s == 2097152:
        enc_2097152_runs = enc_times_us[:10]
        dec_2097152_runs = dec_times_us[:10]

    # guarda nas listas para o gráfico a média e o desvio padrão
    aes_enc.append(statistics.mean(enc_times_us))
    aes_encstd.append(statistics.stdev(enc_times_us))

    aes_dec.append(statistics.mean(dec_times_us))
    aes_decstd.append(statistics.stdev(dec_times_us))

for i in range(1, 11):
    data = os.urandom(2097152)

    ciphertext = aes_encrypt(data)

    enc_time = timeit.timeit(lambda: aes_encrypt(data), number=1) * 1e6
    dec_time = timeit.timeit(lambda: aes_decrypt(ciphertext), number=1) * 1e6

    enc_diff_files_runs.append(enc_time)
    dec_diff_files_runs.append(dec_time)

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
def plot_same_vs_diff_files():
    runs = list(range(1, 11))

    fig, axes = plt.subplots(1, 2, figsize=(16, 6), sharey=True)
    fig.suptitle("AES Execution Time Comparison (File Size = 2097152 bytes)", fontsize=13)

    # --- painel esquerdo: mesmo ficheiro, 10 execuções ---
    axes[0].plot(runs, enc_2097152_runs, marker='o', linestyle='-', color='steelblue', label="Encryption")
    axes[0].plot(runs, dec_2097152_runs, marker='s', linestyle='--', color='tomato',   label="Decryption")
    axes[0].set_title("Same file – repeated runs")
    axes[0].set_xlabel("Run number")
    axes[0].set_ylabel("Time (microseconds)")
    axes[0].legend()
    axes[0].grid(True, linestyle='--', alpha=0.6)

    # --- painel direito: ficheiros diferentes, 1 execução cada ---
    axes[1].plot(runs, enc_diff_files_runs, marker='o', linestyle='-', color='steelblue', label="Encryption")
    axes[1].plot(runs, dec_diff_files_runs, marker='s', linestyle='--', color='tomato',   label="Decryption")
    axes[1].set_title("Different files – one run each")
    axes[1].set_xlabel("File number")
    axes[1].legend()
    axes[1].grid(True, linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.savefig("plots/aes_same_vs_diff_files.png", dpi=300)
    plt.show()

run_aes()
plot_aes()
plot_same_vs_diff_files()