# install dependencies 
sudo apt-get update
sudo apt-get install -y build-essential python3-pip supervisor
pip3 install plumbum toml supervisor-wildcards



# install go
cd ~
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.9.linux-amd64.tar.gz
echo "e858173b489ec1ddbe2374894f52f53e748feed09dde61be5b4b4ba2d73ef34b go1.19.9.linux-amd64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.9.linux-amd64.tar.gz
rm go1.19.9.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version


# install bwm-ng
cd ~
sudo apt-get -y install build-essential
sudo apt-get -y install autoconf
git clone https://github.com/vgropp/bwm-ng.git
cd bwm-ng/
./autogen.sh
make
sudo make install
cd ~


# build timeservice
cd ~
git clone -b miscreant https://github.com/aaronbojarski/scion-time.git

cd ~/scion-time
go build timeservice.go timeservicex.go
openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out testnet/gen/tls.crt -keyout testnet/gen/tls.key -config testnet/tls-cert.conf


# start bwm-ng



# start server


