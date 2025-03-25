# Secure and Dependable Clock Synchronization on Next-Generation Networks

Secure and dependable clock synchronization is an essential prerequisite for many industries with applications in finance, telecommunication, electric power production and distribution, or environmental monitoring.

Current best practice to achieve large-scale clock synchronization relies on global navigation satellite systems (GNSSes) at the considerable risk of being exposed to outages, malfunction, or attacks against availability and accuracy. Natural disasters like solar superstorms also have the potential to hit and severely impact GNSSes.

It is therefore all too apparent that clock synchronization solely based on GNSSes as global reference clocks does not fulfill fundamental dependability requirements for systems that serve indispensable functionalities in our society. Facing these concerns, governments have issued mandates to protect critical infrastructure services from disruption to GNSS services, including a 2020 US Executive Order. Operators and equipment manufacturers are encouraged to intensify research and development of alternative technologies in this space.

Aiming to join these efforts, we are proposing G-SINC: a novel global, Byzantine fault-tolerant clock synchronization approach that does not place trust in any single entity and is able to tolerate a fraction of faulty entities while still maintaining accurate synchronization on a global scale among otherwise sovereign network topologies. G-SINC can be implemented as a fully backward compatible active standby solution for existing time synchronization deployments.

![G-SINC architecture overview](/doc/overview.png)

This is achieved by building on the solid body of fault-tolerant clock synchronization research dating all the way back to the 1980s and the SCION Internet architecture providing required resilience and security properties at the network level as an intrinsic consequence of its underlying design principles. Besides the possibility to use multiple distinct network paths in parallel for significantly improved fault-tolerance, we highlight the fact that SCION paths are reversible and therefore symmetric. Hence, they help to increase time synchronization precision compared to clock offset measurements over the often asymmetric paths in today’s Internet.

We are currently building out the first end-to-end implementation of G-SINC which is contained in this repository.


## Publication

G-SINC: Global Synchronization Infrastructure for Network Clocks.
Marc Frei, Jonghoon Kwon, Seyedali Tabaeiaghdaei, Marc Wyss, Christoph Lenzen, and Adrian Perrig.
In Proceedings of the Symposium on Reliable Distributed Systems (SRDS) 2022.
\[[pdf](https://netsec.ethz.ch/publications/papers/G-SINC.pdf)\], \[[doi](https://doi.org/10.1109/SRDS55811.2022.00021)\], \[[arXiv](https://arxiv.org/abs/2207.06116)\]


## Installing prerequisites for a SCION test environment

Reference platform: Ubuntu 24.04 LTS, Go 1.24.1

On x86-64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.24.1.linux-amd64.tar.gz
echo "cb2396bae64183cdccf81a9a6df0aea3bce9511fc21469fb89a0c00470088073 go1.24.1.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
rm go1.24.1.linux-amd64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile
go version
```

On ARM64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.24.1.linux-arm64.tar.gz
echo "8df5750ffc0281017fb6070fba450f5d22b600a02081dceef47966ffaf36a3af go1.24.1.linux-arm64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.24.1.linux-arm64.tar.gz
rm go1.24.1.linux-arm64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile
go version
```

## Setting up a SCION test environment

```
...
```

## Starting the SCION test network

```
...
```

## Running the server

In session no. 1, run server at `1-ff00:0:133,127.0.0.101:10123`:

```
sudo $SCION_TIME_PATH/bin/timeservice server -verbose -config $SCION_TIME_PATH/testnet/test-server-ip.toml
```

## Querying SCION-based servers

In an additional session, query server at `1-ff00:0:133,127.0.0.101:10123` from `2-ff00:0:222,[fd00:f00d:cafe::7f00:55]`:

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon 127.0.0.108:30255 -local 2-ff00:0:212,127.0.0.109 -remote 1-ff00:0:133,127.0.0.101:10123
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon '[fd00:f00d:cafe::7f00:54]:30255' -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]' -remote 1-ff00:0:133,127.0.0.101:10123
```

### Querying a SCION-based server with SCION Packet Authenticator Option (SPAO)

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon 127.0.0.108:30255 -local 2-ff00:0:212,127.0.0.108 -remote 1-ff00:0:133,127.0.0.101:10123 -auth spao
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon '[fd00:f00d:cafe::7f00:54]:30255' -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]' -remote 1-ff00:0:133,127.0.0.101:10123 -auth spao
```

### Querying a SCION-based server with Network Time Security (NTS)

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon '[fd00:f00d:cafe::7f00:54]:30255' -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]' -remote 1-ff00:0:133,127.0.0.101:14460 -auth nts -ntske-insecure-skip-verify
```

### Querying a SCION-based server with SPAO and NTS

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -daemon '[fd00:f00d:cafe::7f00:54]:30255' -local '2-ff00:0:222,[fd00:f00d:cafe::7f00:55]' -remote 1-ff00:0:133,127.0.0.101:14460 -auth spao,nts -ntske-insecure-skip-verify
```

### Querying a SCION-based server via IP

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -local 0-0,127.0.0.109 -remote 0-0,127.0.0.101:123
```

### Querying a SCION-based server via IP with NTS

```
$SCION_TIME_PATH/bin/timeservice tool -verbose -local 0-0,127.0.0.109 -remote 0-0,127.0.0.101:4460 -auth nts -ntske-insecure-skip-verify
```

## Stopping the SCION test network

```
...
```
