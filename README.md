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
\[[doi](https://doi.org/10.1109/SRDS55811.2022.00021)\], \[[arXiv](https://arxiv.org/abs/2207.06116)\]


## Running a simple IP-based server

Reference platform: Ubuntu 22.04 LTS, Go 1.19.7; see [below](https://github.com/marcfrei/scion-time/edit/main/README.md#installing-prerequisites-for-a-scion-test-environment).

```
cd ~
git clone https://github.com/marcfrei/scion-time.git

cd ~/scion-time
go build timeservice.go timeservicex.go

~/scion-time/timeservice server -verbose -local 0-0,0.0.0.0:10123
```

## Querying an IP-based server

In an additional session:

```
~/scion-time/timeservice tool -verbose -local 0-0,0.0.0.0:0 -remote 0-0,127.0.0.1:10123
```

## Installing prerequisites for a SCION test environment

Reference platform: Ubuntu 22.04 LTS, Go 1.19.7

```
sudo apt-get update
sudo apt-get install -y build-essential python3-pip supervisor
pip3 install plumbum toml supervisor-wildcards
```

On x86-64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.7.linux-amd64.tar.gz
echo "7a75720c9b066ae1750f6bcc7052aba70fa3813f4223199ee2a2315fd3eb533d go1.19.7.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.7.linux-amd64.tar.gz
rm go1.19.7.linux-amd64.tar.gz
echo >> .bash_profile
echo 'export PATH=$PATH:/usr/local/go/bin' >> .bash_profile
source ~/.bash_profile
go version
```

On ARM64:

```
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.7.linux-arm64.tar.gz
echo "071ea7bf386fdd08df524859b878d99fc359e491e7ad65c1c1cc55b67972c882 go1.19.7.linux-arm64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.7.linux-arm64.tar.gz
rm go1.19.7.linux-arm64.tar.gz
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
rm -rf bin/*
go build -o ./bin/ ./control/cmd/control
go build -o ./bin/ ./daemon/cmd/daemon
go build -o ./bin/ ./dispatcher/cmd/dispatcher
go build -o ./bin/ ./router/cmd/router
go build -o ./bin/ ./scion/cmd/scion
go build -o ./bin/ ./scion-pki/cmd/scion-pki

cd ~
git clone https://github.com/marcfrei/scion-time.git

cd ~/scion-time
go build timeservice.go timeservicex.go
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

In session no. 1, run server at `1-ff00:0:111,10.1.1.11:123`:

```
sudo ip netns exec netns0 ~/scion-time/timeservice server -verbose -config ~/scion-time/testnet/gen-eh/ASff00_0_111/ts1-ff00_0_111-1.toml -daemon 10.1.1.11:30255 -local 1-ff00:0:111,10.1.1.11:123
```

In session no. 2, run server at `1-ff00:0:112,10.1.1.12:123`:

```
sudo ip netns exec netns1 ~/scion-time/timeservice server -verbose -config ~/scion-time/testnet/gen-eh/ASff00_0_112/ts1-ff00_0_112-1.toml -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12:123
```

## Querying SCION-based servers

In an additional session, query server at `1-ff00:0:111,10.1.1.11:123` from `1-ff00:0:112,10.1.1.12`:

```
sudo ip netns exec netns1 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12:0 -remote 1-ff00:0:111,10.1.1.11:123
```

Or query server at `1-ff00:0:112,10.1.1.12:123` from `1-ff00:0:111,10.1.1.11`:

```
sudo ip netns exec netns0 ~/scion-time/timeservice tool -verbose -daemon 10.1.1.11:30255 -local 1-ff00:0:111,10.1.1.11:0 -remote 1-ff00:0:112,10.1.1.12:123
```

## Synchronizing with a SCION-based server

In session no. 1, run server at `1-ff00:0:111,10.1.1.11:123`:

```
sudo ip netns exec netns0 ~/scion-time/timeservice server -verbose -config ~/scion-time/testnet/gen-eh/ASff00_0_111/ts1-ff00_0_111-1.toml -daemon 10.1.1.11:30255 -local 1-ff00:0:111,10.1.1.11:123
```

And in session no. 2, synchronize node `1-ff00:0:112,10.1.1.12` with server at `1-ff00:0:111,10.1.1.11:123`:

```
sudo ip netns exec netns1 ~/scion-time/timeservice client -verbose -config ~/scion-time/testnet/test-ff00_0_111-1.toml -daemon 10.1.1.12:30255 -local 1-ff00:0:112,10.1.1.12:0
```

## Stopping the SCION test network

```
export SCION_BIN=~/scion/bin
cd ~/scion-time/testnet

./supervisor/supervisor.sh stop all
```
