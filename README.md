# Homomorphic Encryption Benchmark for Encrypted Control

This repository provides a benchmarking framework for various Homomorphic Encryption (HE) schemes in the context of **Encrypted Control**.

## Overview

Encrypted Control is an emerging field that utilizes Homomorphic Encryption (HE) and Fully Homomorphic Encryption (FHE) to secure controller computations over networks. This allows control loops to operate on encrypted data, preserving privacy against malicious attackers or untrusted cloud providers.

This project aims to benchmark the performance (computation time, ciphertext expansion, noise growth) of different HE schemes when applied to standard control algorithms (e.g., PID, State-Space controllers).

## Project Structure

- `benchmarks/`: Scripts for running timing and performance experiments.
- `src/he_toolkit/`: Implementation of HE schemes (wrappers and custom implementations).
- `results/`: Output directory for raw data and plots.
- `notebooks/`: Jupyter notebooks for analysis.

## Installation

1. Clone the repository.
2. Create a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Implemented Schemes

- **Paillier** (Partial HE): Supports additive homomorphism. Implemented using `python-paillier`.

## Usage

*Coming soon: Instructions on how to run the benchmark runner.*
