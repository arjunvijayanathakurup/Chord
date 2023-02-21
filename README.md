# Simple Distributed Storage based on Chord
A secure simple distributed storage based on Chord protocol.

This project is an implementation of Chord, a protocol for building peer-to-peer (P2P) systems, as described in the paper by Ion Stoica, Robert Morris, David Karger, M. Frans Kaashoek, and Hari Balakrishnan: [Chord: A Scalable Peer-to-peer Lookup Service for Internet Applications](https://people.eecs.berkeley.edu/~istoica/papers/2003/chord-ton.pdf).

The goal of this project is to implement a simple distributed storage system for storing text files on top of Chord. The Chord protocol provides a way to locate the node responsible for a given key, in a scalable and fault-tolerant manner. This implementation should be secure and handle nodes joining and leaving the network gracefully.

### Protocol
The Chord protocol and algorithms are described in the paper. There are two ways to implement the protocol: iteratively or recursively. This implementation will use an iterative approach, in which each node will be able to respond to any incoming calls immediately without blocking to wait on responses from other nodes. An iterative implementation of the pseudocode for the "find successor" function is available [here](https://cit.dixie.edu/cs/3410/asst_chord.html).
