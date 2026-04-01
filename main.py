from aes import run_aes, plot_aes, plot_same_vs_diff_files
from rsa2048 import run_rsa, plot_rsa
from sha256 import run_sha, plot_sha

run_aes()
plot_aes()
plot_same_vs_diff_files()

run_rsa()
plot_rsa()

run_sha()
plot_sha()

import aes_vs_rsa
import aes_vs_sha256
