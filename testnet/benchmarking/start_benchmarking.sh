# This script will create requests with different versions
# 1. ip nonauth
# 2. ip nts
# 3. scion nonauth
# 4. scion spao
# 5. scion nts
# 6. scion spao nts



# install go
cd ~
sudo rm -rf /usr/local/go
curl -LO https://golang.org/dl/go1.19.7.linux-arm64.tar.gz
echo "071ea7bf386fdd08df524859b878d99fc359e491e7ad65c1c1cc55b67972c882 go1.19.7.linux-arm64.tar.gz" | sha256sum -c
sudo tar -C /usr/local -xzf go1.19.7.linux-arm64.tar.gz
rm go1.19.7.linux-arm64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go version

# build timeservice
cd ~
sudo rm -r scion-time
git clone -b miscreant https://github.com/aaronbojarski/scion-time.git
cd ~/scion-time
go build timeservice.go timeservicex.go



cd ~/scion-time

sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/ip_nonauth_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done


sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/ip_nts_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done


sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion_nonauth_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done


sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion_spao_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done


sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion_nts_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done


sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

for c in 1 2 4 8 16 32 64 128 192 256 320 384;
do 
    for i in $(seq 1 $c)
    do 
        sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion_spao_nts_benchmark.toml &
    done
    sleep 20
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
    sleep 5
done

echo "Done"