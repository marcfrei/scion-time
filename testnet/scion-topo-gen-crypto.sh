#!/usr/bin/env bash
set -Eeuo pipefail

cd ~/scion

rm -rf gen*
printf '#!/bin/bash\necho "0.0.0.0"' > tools/docker-ip
sed -i "s/DEFAULT_NETWORK = \"127\.0\.0\.0\/8\"/DEFAULT_NETWORK = \"10\.0\.0\.0\/16\"/" tools/topology/net.py
tools/topogen.py -c ~/scion-time/testnet/default4.topo
git checkout --quiet tools/topology/net.py
git checkout --quiet tools/docker-ip

export PYTHONPATH=python/:.
~/scion-time/testnet/scion-topo-add-drkey.py

cd ~/scion-time/testnet/

gen_delete_crypto () {
	rm -rf gen/certs
	rm -rf gen/trcs
}

gen_copy_crypto () {
	cp -r ~/scion/gen/certs gen/
	cp -r ~/scion/gen/trcs gen/
}

isd_delete_crypto () {
	rm -rf gen/$1/trcs
}

isd_copy_crypto () {
	cp -r ~/scion/gen/$1/trcs gen/$1/
}

as_delete_crypto () {
	rm -rf gen/$1/certs
	rm -rf gen/$1/crypto
	rm -rf gen/$1/keys
}

as_copy_crypto () {
	cp -r ~/scion/gen/$1/certs gen/$1/
	cp -r ~/scion/gen/$1/crypto gen/$1/
	cp -r ~/scion/gen/$1/keys gen/$1/
}

eh_delete_crypto () {
	rm -rf gen-eh/$1/certs
	rm -rf gen-eh/$1/crypto
	rm -rf gen-eh/$1/keys
}

eh_copy_crypto () {
	cp -r ~/scion/gen/$1/certs gen-eh/$1/
	cp -r ~/scion/gen/$1/crypto gen-eh/$1/
	cp -r ~/scion/gen/$1/keys gen-eh/$1/
}

eh_delete_crypto ASff00_0_111
eh_delete_crypto ASff00_0_112

as_delete_crypto ASff00_0_110
as_delete_crypto ASff00_0_111
as_delete_crypto ASff00_0_112
as_delete_crypto ASff00_0_120
as_delete_crypto ASff00_0_121
as_delete_crypto ASff00_0_122
as_delete_crypto ASff00_0_130
as_delete_crypto ASff00_0_131
as_delete_crypto ASff00_0_132
as_delete_crypto ASff00_0_133
as_delete_crypto ASff00_0_210
as_delete_crypto ASff00_0_211
as_delete_crypto ASff00_0_212
as_delete_crypto ASff00_0_220
as_delete_crypto ASff00_0_221
as_delete_crypto ASff00_0_222

isd_delete_crypto ISD1
isd_delete_crypto ISD2

gen_delete_crypto

eh_copy_crypto ASff00_0_111
eh_copy_crypto ASff00_0_112
as_copy_crypto ASff00_0_110
as_copy_crypto ASff00_0_111
as_copy_crypto ASff00_0_112
as_copy_crypto ASff00_0_120
as_copy_crypto ASff00_0_121
as_copy_crypto ASff00_0_122
as_copy_crypto ASff00_0_130
as_copy_crypto ASff00_0_131
as_copy_crypto ASff00_0_132
as_copy_crypto ASff00_0_133
as_copy_crypto ASff00_0_210
as_copy_crypto ASff00_0_211
as_copy_crypto ASff00_0_212
as_copy_crypto ASff00_0_220
as_copy_crypto ASff00_0_221
as_copy_crypto ASff00_0_222
isd_copy_crypto ISD1
isd_copy_crypto ISD2
gen_copy_crypto

rm -rf gen-cache
rm -rf gen-certs
mkdir gen-cache
mkdir gen-certs

rm -f gen/tls.crt
rm -f gen/tls.key

cd ~/scion-time/
sh testnet/tls-gen-cert.sh
