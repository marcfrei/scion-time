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


## Running a simple IP-based server

Reference platform: Ubuntu 24.04 LTS, Go 1.25.1; see [below](https://github.com/marcfrei/scion-time/edit/main/README.md#installing-prerequisites-for-a-scion-test-environment).

```
cd ~
git clone https://github.com/marcfrei/scion-time.git

cd ~/scion-time
go build timeservice.go timeservice_t.go

sudo ~/scion-time/timeservice server -verbose -config testnet/test-server.toml
```

## Querying an IP-based server

In an additional session:

```
~/scion-time/timeservice tool -verbose -local 0-0,0.0.0.0 -remote 0-0,127.0.0.1:123
```

## Querying an IP-based server with Network Time Security (NTS)

In an additional session:

```
~/scion-time/timeservice tool -verbose -local 0-0,0.0.0.0 -remote 0-0,127.0.0.1:4460 -auth nts -ntske-insecure-skip-verify
```

## Installing prerequisites for a SCION test environment

Reference platform: Ubuntu 24.04 LTS, Go 1.25.1

```
sudo apt-get update
sudo apt-get install -y build-essential python3-plumbum python3-toml supervisor
```

On x86-64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.25.1.linux-amd64.tar.gz
echo "7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e go1.25.1.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
rm go1.25.1.linux-amd64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile
go version
```

On ARM64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.25.1.linux-arm64.tar.gz
echo "65a3e34fb2126f55b34e1edfc709121660e1be2dee6bdf405fc399a63a95a87d go1.25.1.linux-arm64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.25.1.linux-arm64.tar.gz
rm go1.25.1.linux-arm64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile
go version
```

## Setting up a SCION test environment

```
cd ~
git clone https://github.com/scionproto/scion.git

cd ~/scion
git checkout v0.12.0
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./router/cmd/router
go build -o ./bin/ ./scion/cmd/scion
go build -o ./bin/ ./scion-pki/cmd/scion-pki

cd ~
git clone https://github.com/marcfrei/scion-time.git

cd ~/scion-time
go build timeservice.go timeservice_t.go
```

## Starting the SCION test network

```
export SCION_BIN=~/scion/bin
cd ~/scion-time/testnet

rm -rf logs
./scion-topo-gen-crypto.sh
./testnet-up.sh

./supervisor/supervisor.sh reload && sleep 1
./supervisor/supervisor.sh start all
```

## Running the servers

In session no. 1, run server at `1-ff00:0:111,10.1.1.11:10123`:

```
cd ~/scion-time
sudo ip netns exec netns0 ./timeservice server -verbose -config testnet/gen-eh/ASff00_0_111/ts1-ff00_0_111-1.toml
```

In session no. 2, run server at `1-ff00:0:112,10.1.1.12:10123`:

```
cd ~/scion-time
sudo ip netns exec netns1 ./timeservice server -verbose -config testnet/gen-eh/ASff00_0_112/ts1-ff00_0_112-1.toml
```

## Querying SCION-based servers

In an additional session, query server at `1-ff00:0:111,10.1.1.11:10123` from `1-ff00:0:112,10.1.1.12`:

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12 -remote 1-ff00:0:111,10.1.1.11:10123
```

Or query server at `1-ff00:0:112,10.1.1.12:10123` from `1-ff00:0:111,10.1.1.11`:

```
sudo ip netns exec netns0 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.11:30255 -local 1-ff00:0:111,10.1.1.11 -remote 1-ff00:0:112,10.1.1.12:10123
```

### Querying a SCION-based server with SCION Packet Authenticator Option (SPAO)

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12 -remote 1-ff00:0:111,10.1.1.11:10123 -auth spao
```

### Querying a SCION-based server with Network Time Security (NTS)

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12 -remote 1-ff00:0:111,10.1.1.11:14460 -auth nts -ntske-insecure-skip-verify
```

### Querying a SCION-based server with SPAO and NTS

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12 -remote 1-ff00:0:111,10.1.1.11:14460 -auth spao,nts -ntske-insecure-skip-verify
```

### Querying a SCION-based server via IP

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -local 0-0,10.1.1.12 -remote 0-0,10.1.1.11:123
```

### Querying a SCION-based server via IP with NTS

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -local 0-0,10.1.1.12 -remote 0-0,10.1.1.11:4460 -auth nts -ntske-insecure-skip-verify
```

## Synchronizing with a SCION-based server

In session no. 1, run server at `1-ff00:0:111,10.1.1.11:10123`:

```
cd ~/scion-time
sudo ip netns exec netns0 ./timeservice server -verbose -config testnet/gen-eh/ASff00_0_111/ts1-ff00_0_111-1.toml
```

And in session no. 2, synchronize node `1-ff00:0:112,10.1.1.12` with server at `1-ff00:0:111,10.1.1.11:10123`:

```
cd ~/scion-time
sudo ip netns exec netns1 ./timeservice client -verbose -config testnet/gen-eh/ASff00_0_112/test-client.toml
```

## Stopping the SCION test network

```
export SCION_BIN=~/scion/bin
cd ~/scion-time/testnet

./supervisor/supervisor.sh stop all
```
