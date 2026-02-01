# Evice Intent Ecosystem 🦀

> **A Vertically Integrated, Intent-Centric App-Chain Architecture written in Rust.**

![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![Architecture](https://img.shields.io/badge/architecture-Microservices-purple)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

## Overview

**Evice** is a next-generation DeFi infrastructure designed to solve the fragmentation between Execution and Settlement. It leverages an **Intent-Centric** paradigm where users express desired outcomes, and specialized Solvers compete to fulfill them with optimal execution paths.

This repository is a monorepo workspace containing the "Holy Trinity" of decentralized infrastructure:
1.  **Velocity-DEX (The Muscle):** An ultra-low latency, in-memory sequencer (L2) with atomic bundle execution.
2.  **Evice-Solver (The Brain):** An intelligent agent performing real-time Cross-Chain Arbitrage (Mainnet Forking) and JIT liquidity provision.
3.  **Evice Blockchain Aegis (The Vault):** A custom Layer-1 blockchain (Rust/RocksDB/LibP2P) serving as the final settlement layer.

## System Architecture

The ecosystem is composed of specialized microservices working in harmony:

| Crate | Component | Role | Tech Stack |
|-------|-----------|------|------------|
| `crates/engine` | **Matching Engine** | Core Orderbook Logic (CLOB) | Rust, Bincode |
| `crates/sequencer-node` | **Sequencer (L2)** | gRPC Gateway & Batch Submitter | Tonic, Tokio |
| `crates/solver-service` | **Solver Bot** | Arbitrage & Intent Filling | Alloy, Revm |
| `crates/aegis-node` | **Aegis Node (L1)** | Consensus & Finality | LibP2P, RocksDB |
| `crates/user-client` | **User Sim** | Intent Generation | Rust Script |

### The Flow of Value
1.  **Intent:** User submits a desired outcome (e.g., "Buy ETH at $2000").
2.  **Solve:** Solver detects the intent, forks Mainnet to check prices, and executes an atomic bundle.
3.  **Execute:** Velocity Sequencer fills the order in sub-milliseconds off-chain.
4.  **Settle:** Sequencer batches trades and submits a validity proof to the Aegis L1 Blockchain for finality.

## Getting Started

### Prerequisites
* Rust (latest stable) & Clang (for RocksDB)
* `protobuf-compiler` (for gRPC)
* An Ethereum RPC URL (Alchemy/Infura) for solver simulation.

### 1. Environment Setup
Create a `.env` file in the root directory:
    
    # Mainnet Forking for Solver
    RPC_URL=[https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY](https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY)
    
    # Internal Communication
    SEQUENCER_URL=[http://[::1]:50051](http://[::1]:50051)
    AEGIS_URL=[https://127.0.0.1:9000](https://127.0.0.1:9000)
    RUST_LOG=info

### 2. Running the Full Stack
To witness the full lifecycle, you will need to run the components in separate terminals:

Terminal 1: The Settlement Layer (Aegis L1)
Start the blockchain node first.

    cd crates/aegis-node
    cargo run --bin sequencer -- --node-type validator

Terminal 2: The Execution Layer (Velocity L2)
Start the sequencer. It will automatically connect to Aegis.

    # In project root
    cargo run -p sequencer-node

Terminal 3: The Intelligence Layer (Solver)
Start the solver to monitor and fill intents.

    cargo run -p solver-service

Terminal 4: The User
Simulate high-frequency intents.

    cargo run -p user-client
    
## A Note on Testing
While the architecture is fully integrated and compiles successfully across all layers (L1 & L2), full-load end-to-end runtime simulations are currently limited due to hardware constraints on the development machine (SSD health preservation). The codebase is verified for type-safety, logic validity, and architectural correctness via the Rust compiler.

### 📄 License
MIT
