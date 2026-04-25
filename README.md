# BGP Routing Table Library

A highly optimized in-memory BGP routing table (RIB) written in Go. This library provides a concurrent, highly memory-efficient data structure for storing IPv4 and IPv6 BGP routing information, designed specifically for ingesting full Internet routing tables.

## Features

- **Radix Trie Storage**: A custom binary trie implementation optimized for IP routing. It replaces the first 8 levels of tree traversal with a single O(1) array lookup (`ipv4Root[256]` and `ipv6Root[32]`) which drastically speeds up longest-prefix matching.
- **Add-Path Support**: Every node safely stores multiple paths (keyed by BGP Path ID) natively.
- **Memory Deduplication**: Heavy BGP Path Attributes (AS Paths, Communities, Large Communities, LocalPref) are globally deduplicated using a reference-counted hash table. This reduces memory footprint by up to 50% compared to standard representations.
- **Concurrency-Safe**: Full read/write locking split between IPv4 and IPv6 operations allows concurrent ingestion without blocking lookups.

## Memory Optimized Storage

BGPWatch utilizes a highly memory-optimized Radix Trie combined with a Deduplicated Attribute Table. If a remote peer sends multiple paths (Add-Path) for the same prefix, the daemon deduplicates the structural information, saving significant memory.

Here is how 6 different paths for the same prefix (e.g. `8.8.8.0/24`) are stored efficiently in the peer's RIB in RAM:

```mermaid
graph TD
    classDef array fill:#2b303a,stroke:#4a5568,color:#e2e8f0
    classDef node fill:#1a365d,stroke:#2b6cb0,color:#e2e8f0
    classDef map fill:#553c9a,stroke:#805ad5,color:#e2e8f0
    classDef attr fill:#276749,stroke:#48bb78,color:#e2e8f0
    
    subgraph "1. IPv4 Root Array (Indexed by 1st Octet)"
        Root[ipv4Root array]:::array
        Idx["Index [8] (for 8.x.x.x)"]:::array
        Root --- Idx
    end

    subgraph "2. Binary Trie (Traversing bits 9 to 24)"
        Node1[node]:::node
        Node2[node]:::node
        Node3["node (Target: 8.8.8.0/24)"]:::node
        
        Idx -->|bit 0| Node1
        Node1 -.->|...| Node2
        Node2 -->|bit 1| Node3
    end

    subgraph "3. Path Map (Stored on the Target Node)"
        PathsMap["paths map[uint32]*RouteAttributes"]:::map
        
        Path1["PathID: 101"]:::map
        Path2["PathID: 102"]:::map
        Path3["PathID: 103"]:::map
        Path4["PathID: 104"]:::map
        Path5["PathID: 105"]:::map
        Path6["PathID: 106"]:::map
        
        Node3 --> PathsMap
        PathsMap --- Path1
        PathsMap --- Path2
        PathsMap --- Path3
        PathsMap --- Path4
        PathsMap --- Path5
        PathsMap --- Path6
    end

    subgraph "4. Deduplicated Attribute Table (Global to the RIB)"
        AttrTable["attrTable map[uint64]*RouteAttributes"]:::attr
        
        AttrA["*RouteAttributes<br/>(AS Path: 15169, 3356)<br/>RefCount: 4"]:::attr
        AttrB["*RouteAttributes<br/>(AS Path: 15169, 1299)<br/>RefCount: 1"]:::attr
        AttrC["*RouteAttributes<br/>(AS Path: 15169, 174)<br/>RefCount: 1"]:::attr
        
        AttrTable --- AttrA
        AttrTable --- AttrB
        AttrTable --- AttrC
    end

    %% Pointers from Path Map to Deduplicated Attributes
    Path1 ==>|pointer| AttrA
    Path2 ==>|pointer| AttrA
    Path3 ==>|pointer| AttrB
    Path4 ==>|pointer| AttrA
    Path5 ==>|pointer| AttrC
    Path6 ==>|pointer| AttrA
```
