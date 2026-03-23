import hashlib
import statistics
import timeit

sizes = [8,64,512,4096,32768,262144,2097152]

# Função de hash SHA-256
def sha256_hash(data):
    return hashlib.sha256(data).digest()

# Listas para guardar médias e desvios
sha_mean_list = []
sha_std_list = []

repeats = 30  # número de repetições para o timeit

for s in sizes:
    # Lê o ficheiro
    with open(f"ficheiro_{s}.txt","rb") as f:
        data = f.read()

    # Função lambda para timeit
    hash_func = lambda: sha256_hash(data)

    # Mede várias vezes
    times = timeit.repeat(hash_func, repeat=repeats, number=1)

    # Converte para microsegundos
    times_us = [t*1e6 for t in times]

    # Calcula média e desvio padrão
    mean = statistics.mean(times_us)
    std = statistics.stdev(times_us)

    sha_mean_list.append(mean)
    sha_std_list.append(std)

    # Print
    print(s, "SHA:", f"{mean:.2f} ± {std:.2f}")


import matplotlib.pyplot as plt

plt.figure(figsize=(10,6))

# Plot com barras de erro
plt.errorbar(sizes, sha_mean_list, yerr=sha_std_list, marker='o', linestyle='-', label="SHA-256")

# Escala log no eixo X
plt.xscale("log")
plt.xticks(sizes, sizes)  # marca explicitamente os 7 tamanhos

# Adiciona valores acima de cada ponto
for x, y in zip(sizes, sha_mean_list):
    plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

plt.xlabel("File size (bytes)")
plt.ylabel("Time (microseconds)")
plt.title("SHA-256 Performance (timeit)")
plt.grid(True, which="both", linestyle='--', alpha=0.6)
plt.legend()
plt.savefig("sha256_performance_timeit.png", dpi=300)
plt.show()

def run_sha():
    return sizes, sha_mean_list, sha_std_list