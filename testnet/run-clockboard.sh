#!/bin/sh
set -eu
if [ $# -lt 1 ]; then
	echo "Usage: $0 BUCKETS_CSV [clockboard options]" >&2
	exit 1
fi
case $1 in
	/*) buckets=$1 ;;
	*) buckets=$PWD/$1 ;;
esac
shift
cd "$(dirname "$0")"
exec go run -C clockboard . -buckets "$buckets" -offplot "$PWD/offplot" "$@"
