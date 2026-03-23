from aes_benchmark import run_aes
from sha256_benchmark import run_sha
import matplotlib.pyplot as plt

# ir buscar os dados
sizes, aes_enc_mean, aes_enc_std, _, _ = run_aes()
_, sha_mean, sha_std = run_sha()

plt.figure(figsize=(10,6))

# AES Encryption
plt.errorbar(sizes, aes_enc_mean, yerr=aes_enc_std, marker='o', linestyle='-', label="AES Encryption")

# SHA-256
plt.errorbar(sizes, sha_mean, yerr=sha_std, marker='o', linestyle='-', label="SHA-256")

# escala log no eixo X
plt.xscale("log")
plt.xticks(sizes, sizes)

# valores nos pontos
for x, y in zip(sizes, aes_enc_mean):
    plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

for x, y in zip(sizes, sha_mean):
    plt.text(x, y*1.02, f"{int(y)}", ha='center', va='bottom', fontsize=8)

plt.xlabel("File size (bytes)")
plt.ylabel("Time (microseconds)")
plt.title("AES Encryption vs SHA-256 Performance")
plt.grid(True, which="both", linestyle='--', alpha=0.6)
plt.legend()

plt.savefig("aes_vs_sha256.png", dpi=300)
plt.show()