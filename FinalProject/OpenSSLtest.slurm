#!/bin/bash
#SBATCH --job-name=test_openssl
#SBATCH --output=openssl_test.out
#SBATCH --error=openssl_test.err
#SBATCH --time=00:02:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=512M

# Load OpenSSL module if your cluster uses modules
# (Check available modules with: module avail openssl)
module load openssl
module load gcc

# Compile
g++ OpenSSLtest.cpp -o test_openssl -lssl -lcrypto

# Run
./test_openssl