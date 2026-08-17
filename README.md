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
* The Genesis Block
* Bitcoin's original architecture

Bitcoin Origins is **not Bitcoin** and is not affiliated with the Bitcoin Core project.

## Genesis Block

Bitcoin Origins uses its own independently generated Genesis Block.

This separates the Bitcoin Origins blockchain completely from the Bitcoin network and creates a new blockchain starting from block `0`.

## Network

Bitcoin Origins uses a peer-to-peer network where nodes can connect to each other and synchronize the blockchain.

The default network port used by Bitcoin Origins is:

```text
17474
```

Make sure TCP port `17474` is allowed through your firewall and properly forwarded if you want your node to accept incoming connections from the public network.

Public bootstrap nodes may be provided so that new installations can discover peers and download the blockchain.

## Mining

Bitcoin Origins uses Proof-of-Work mining inspired by the original Bitcoin implementation.

Mining secures the network and allows new blocks to be added to the blockchain.

## Status

> ⚠️ Bitcoin Origins is currently experimental software and under active development.

The protocol, network configuration, blockchain format, and other components may change during development.

Do not use Bitcoin Origins for storing anything of real monetary value.

## Building

Build instructions will be added as the project develops.

The primary development target is currently:

* Windows
* x86 / x64
* C++

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
