# Evice Intent Ecosystem 🦀

> A High-Performance, Intent-Centric DeFi Architecture written in Rust.

![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![Architecture](https://img.shields.io/badge/architecture-Microservices-purple)

## 📖 Overview

**Evice** is a next-generation DeFi infrastructure designed to solve the fragmentation between Execution and Settlement. It leverages an **Intent-Centric** paradigm where users express desired outcomes, and specialized Solvers compete to fulfill them with optimal execution paths.

This repository implements the **Proof-of-Concept (PoC)** featuring a vertically integrated stack:
1.  **Velocity-DEX (Sequencer):** A high-performance, in-memory orderbook engine utilizing specific WAL persistence.
2.  **Evice-Solver (Searcher):** An intelligent agent capable of Cross-Chain Arbitrage simulation (forking Mainnet via Alloy/Reth) and Just-In-Time (JIT) liquidity provisioning.
3.  **Protocol Interfaces:** gRPC-based communication enabling sub-millisecond coordination between Solvers and the Sequencer.

## 🏗 Architecture

The ecosystem operates as a monorepo workspace containing specialized microservices:

| Crate | Role | Description |
|-------|------|-------------|
| `crates/engine` | **The Core** | Ultra-low latency Matching Engine logic (CLOB). |
| `crates/sequencer-node` | **The Server** | gRPC Interface handling order flow and atomic bundle execution. |
| `crates/solver-service` | **The Brain** | Intelligent bot that monitors the engine, simulates profitability on Mainnet (Uniswap V2), and executes atomic bundles. |
| `crates/user-client` | **The User** | Simulation script generating intent flow (Liquidity Takers). |
| `crates/simulator` | **The Sandbox** | EVM Forking environment using `revm` for transaction pre-simulation. |

## 🚀 Getting Started

### Prerequisites
* Rust (latest stable)
* An Ethereum RPC URL (Alchemy/Infura) for Mainnet forking.

### 1. Environment Setup
Create a `.env` file in the root directory:

    RPC_URL=[https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY](https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY)
    SEQUENCER_URL=[http://[::1]:50051](http://[::1]:50051)
    RUST_LOG=info

### 2. Running the Ecosystem
You will need 3 separate terminal windows to observe the full economic cycle.

Terminal 1: The Sequencer (Exchange)
Start the execution environment.

    cargo run -p sequencer-node

Wait until you see: Velocity DEX Engine listening on [::1]:50051

Terminal 2: The Solver (Market Maker)
Start the intelligent solver. It will connect to the sequencer and begin monitoring for arbitrage opportunities against real-time Mainnet prices.

    cargo run -p solver-service

it will log connected and start scanning

Terminal 3: The User (Intent Source)
Simulate a user submitting a high-value Buy Intent.

    cargo run -p user-client

### 3. Verification (What to look for)
In the Solver Terminal, you should witness the following sequence:

1. Detection: Opportunity Check: User wants to BUY at $9100
2. Simulation: Checking Uniswap Price... (Queries Alchemy RPC)
3. Profit Calc: Uniswap: $2800 | Spread: $6300
4. Execution: ✅ ARBITRAGE FOUND! Executing Hedge on Velocity...
5. Settlement: ✅ Bundle Executed!

### 🛠 Technical Highlights
- Atomic Bundles: Solvers execute Fill User + Hedge on External Market instructions atomically. If one fails, the entire bundle reverts.

- Real-time Forking: Utilizes alloy and revm to simulate transactions against current Ethereum Mainnet state without spending real gas.

- Zero-Copy Networking: Optimized gRPC definitions for high-throughput intent propagation.

### 📄 License
MIT