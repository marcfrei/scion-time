#!/usr/bin/env bash
set -Eeuo pipefail

cd ~/scion

rm -rf gen*
printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip
sed -i "s/DEFAULT_NETWORK = \"127\.0\.0\.0\/8\"/DEFAULT_NETWORK = \"10\.0\.0\.0\/16\"/" tools/topology/net.py
tools/topogen.py -c ~/scion-time/testnet/duo/duo.topo
git checkout --quiet tools/topology/net.py
git checkout --quiet tools/docker-ip

sed -i "s/data\[\"Non-core\"]/(data.get(\"Non-core\") or \[])/" acceptance/common/scion.py
export PYTHONPATH=pythonx/:.
~/scion-time/testnet/scion-topo-add-drkey.py
git checkout --quiet acceptance/common/scion.py
