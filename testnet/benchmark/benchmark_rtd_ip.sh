# This script will create requests with different versions
# 1. ip nonauth
# 2. ip nts
# 3. scion nonauth
# 4. scion spao
# 5. scion nts
# 6. scion spao nts


cd ~/scion-time

sudo killall timeservice
sudo killall timeservice
sudo killall timeservice

echo "Nonauth IP"

for iter in `seq 1 20`;
do
    sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion-time/testnet/benchmark/config/ip_nonauth_benchmark.toml
    sleep 5
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
done

echo "Nonauth IP done"

echo "NTS IP"

for iter in `seq 1 20`;
do
    sudo USE_MOCK_KEYS=TRUE ./timeservice benchmark -config ~/scion-time/testnet/benchmark/config/ip_nts_benchmark.toml
    sleep 5
    sudo killall timeservice
    sudo killall timeservice
    sudo killall timeservice
done

echo "NTS IP done"
