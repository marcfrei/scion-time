openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out testnet/gen/tls.crt -keyout testnet/gen/tls.key -config testnet/gen/cert.conf
