# Bitcoin Origins

Bitcoin Origins is a personal cryptocurrency project inspired by the original 2009 release of Bitcoin.

The goal of the project is to recreate the simplicity, architecture, and spirit of early Bitcoin while running as a completely independent blockchain with its own genesis block, network, nodes, and mining system.

## About the Project

Bitcoin Origins is built primarily as an educational and experimental project focused on understanding how Bitcoin works at a low level.

The project explores concepts such as:

* Peer-to-peer networking
* Blockchain synchronization
* Proof-of-Work mining
* Block validation
* Transactions
* Nodes
* Mining job handling
* The Genesis Block
* Bitcoin's original architecture
* External CPU mining
* Mining job distribution and stale-work detection

Bitcoin Origins is **NOT Bitcoin** and is not affiliated with the Bitcoin Core project.

## Genesis Block

Bitcoin Origins uses its own independently generated Genesis Block.

This separates the Bitcoin Origins blockchain completely from the Bitcoin network and creates a new blockchain starting from block `0`.

## Network

Bitcoin Origins uses a peer-to-peer network where nodes can connect to each other, synchronize the blockchain, and propagate newly mined blocks.

The default P2P port used by Bitcoin Origins is:

```text
17474
```

Nodes can currently be connected manually using:

```text
bitcoin-origins.exe -connect=<ip>:17474
```

Example:

```text
bitcoin-origins.exe -connect=192.168.1.50:17474
```

Make sure TCP port `17474` is allowed through your firewall and properly forwarded if you want your node to accept incoming connections from the public network.

Peer discovery and public bootstrap infrastructure are still under development, so manual peer connections may currently be required.

## Mining

Bitcoin Origins uses Proof-of-Work mining inspired by the original Bitcoin implementation.

Mining secures the network and allows new blocks to be added to the blockchain.

### External CPU Miner

Bitcoin Origins includes a separate **external CPU miner**.

The miner connects locally to the Bitcoin Origins node through:

```text
127.0.0.1:17475
```

The external miner:

* Uses multi-threaded CPU mining
* Uses all available logical CPU threads
* Supports multi-processor systems
* Uses SHA-256 midstate optimization
* Receives mining jobs directly from the node
* Submits valid blocks back to the node
* Detects stale mining work automatically
* Requests new work when another node finds a block

The miner has been successfully tested on a dual-CPU system using 24 logical threads.

When another node finds and propagates a new block, the miner detects that its current job is stale and automatically requests updated work.

## Tested Features

The following functionality has been tested between independent Bitcoin Origins nodes:

* Direct P2P connection
* Blockchain synchronization
* Block propagation
* External CPU mining
* Multi-threaded mining
* Dual-CPU / multi-processor mining
* Mining job submission
* Automatic stale-work detection
* Automatic mining job refresh after a new block

## Status

> ⚠️ Bitcoin Origins is currently experimental software and under active development.

The protocol, network configuration, blockchain format, mining protocol, and other components may change during development.

Do not use Bitcoin Origins for storing anything of real monetary value.

## Building

Build instructions will be added as the project develops.

The primary development target is currently:

* Windows
* x86
* C++

Some components and dependencies are based on historical software versions in order to remain close to the original Bitcoin 0.1 architecture.

## Contributing

Contributions, testing, bug reports, and experimentation are welcome.

Feel free to open an issue or submit a pull request.

## License

Bitcoin Origins is released under the **MIT License**.

Parts of the project may contain or be derived from Bitcoin source code and retain their respective copyright notices and licensing information.

See the `LICENSE` file for details.

## Disclaimer

Bitcoin Origins is an independent experimental project created for educational and research purposes.

It is not affiliated with, endorsed by, or officially connected to Bitcoin, Bitcoin Core, or their developers.

## Support

If you'd like to support the project:

**Bitcoin:** `bc1q80t69h70p05d8exv0rmzm4maru84tweh6n3l49`

Thank you! ❤️
