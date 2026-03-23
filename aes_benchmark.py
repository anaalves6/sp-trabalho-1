import os
import statistics
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import timeit

# Tamanhos dos ficheiros
sizes = [8, 64, 512, 4096, 32768, 262144, 2097152]

# Chave AES e nonce fixo (apenas para benchmarking)
key = os.urandom(32)
nonce = os.urandom(16)  # nonce fixo para medir tempos, não para segurança

# Funções de encriptação e decriptação
def aes_encrypt(data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_decrypt(ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Listas para guardar os tempos médios
aes_enc = []
aes_dec = []

aes_encstd = []
aes_decstd = []

# Número de repetições para o timeit
repeats = 30

for s in sizes:
    # Lê o ficheiro
    with open(f"ficheiro_{s}.txt", "rb") as f:
        data = f.read()

    # Define funções lambda para timeit
    enc_func = lambda: aes_encrypt(data)
    # Vamos precisar do ciphertext para a decriptação
    ciphertext = aes_encrypt(data)
    dec_func = lambda: aes_decrypt(ciphertext)

    # Executa timeit.repeat para medir múltiplas vezes
    enc_times = timeit.repeat(enc_func, repeat=repeats, number=1)
    dec_times = timeit.repeat(dec_func, repeat=repeats, number=1)

    # Converte para microsegundos
    enc_times_us = [t * 1e6 for t in enc_times]
    dec_times_us = [t * 1e6 for t in dec_times]

    # Calcula média e desvio padrão
    enc_mean = statistics.mean(enc_times_us)
    enc_std = statistics.stdev(enc_times_us)

    dec_mean = statistics.mean(dec_times_us)
    dec_std = statistics.stdev(dec_times_us)

    # Guarda para o gráfico
    aes_enc.append(enc_mean)
    aes_dec.append(dec_mean)

    aes_encstd.append(enc_std)
    aes_decstd.append(dec_std)


    # Print para verificar
    print(
        s,
        "ENC:", f"{enc_mean:.2f} ± {enc_std:.2f}",
        "DEC:", f"{dec_mean:.2f} ± {dec_std:.2f}"
    )



plt.figure(figsize=(10,6))

# plot com barras de erro
plt.errorbar(sizes, aes_enc, yerr=enc_std, marker='o', linestyle='-', label="Encryption")
plt.errorbar(sizes, aes_dec, yerr=dec_std, marker='o', linestyle='-', label="Decryption")

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
plt.title("AES Performance (CTR Mode) using timeit")
plt.legend()
plt.grid(True, which="both", linestyle='--', alpha=0.6)

plt.savefig("aes_performance_timeit_refined.png", dpi=300)
plt.show()

def run_aes():
    return sizes, aes_enc, aes_encstd, aes_dec, aes_decstd

# Observações para relatório:
# - O tempo de encriptação e decriptação aumenta aproximadamente linearmente com o tamanho do ficheiro.
# - Usamos nonce fixo apenas para benchmarking.
# - Timeit permite medir tempos de execução mais consistentes e repetir várias vezes automaticamente.