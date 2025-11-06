#!/usr/bin/env zsh
#SBATCH --partition=instruction
#SBATCH --time=00:03:00
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=4
#SBATCH --output=static_tasking.output
cd $SLURM_SUBMIT_DIR
g++ -std=c++17 static_tasking.cpp -o static_tasking -I ./ -pthread
./static_tasking

