sudo apt-get install libgnutls28-dev
sudo apt-get install gnutls-bin
sudo apt-get install libtomcrypt-dev
sudo apt-get install nettle-dev
sudo apt-get install pkg-config
curl -LO https://download.tuxfamily.org/chrony/chrony-4.3.tar.gz
tar -xzvf chrony-4.3.tar.gz 
mv chrony-4.3 chrony-4.3-src
mkdir chrony-4.3
cd chrony-4.3-src/
./configure --prefix=/home/ubuntu/chrony-4.3
make
sudo make install


sh /home/ubuntu/scion-time/testnet/tls-gen-cert.sh
sudo systemctl stop chronyd

# Might need to bind address in config file first
sudo /home/ubuntu/chrony-4.3/sbin/chronyd -4 -f /home/ubuntu/scion-time/testnet/benchmarking/chronyNTS.conf