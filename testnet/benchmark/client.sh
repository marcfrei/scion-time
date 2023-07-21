# install go
cd ~
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.9.linux-arm64.tar.gz
echo "b947e457be9d7b52a082c68e42b6939f9cc151f1ad5b3d8fd646ca3352f6f2f1 go1.19.9.linux-arm64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.9.linux-arm64.tar.gz
rm go1.19.9.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version

# build timeservice
cd ~
sudo rm -r scion-time
git clone https://github.com/marcfrei/scion-time.git
cd ~/scion-time
go build timeservice.go timeservicex.go
