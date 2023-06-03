# install go
cd ~
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.9.linux-amd64.tar.gz
echo "e858173b489ec1ddbe2374894f52f53e748feed09dde61be5b4b4ba2d73ef34b go1.19.9.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.9.linux-amd64.tar.gz
rm go1.19.9.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version

# build timeservice
cd ~
sudo rm -r scion-time
git clone https://github.com/marcfrei/scion-time.git
cd ~/scion-time
go build timeservice.go timeservicex.go
