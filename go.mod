module example.com/scion-time

go 1.26.4

require (
	github.com/HdrHistogram/hdrhistogram-go v1.3.0
	github.com/VictoriaMetrics/easyproto v1.2.0
	github.com/gopacket/gopacket v1.7.0
	github.com/miscreant/miscreant.go v0.0.0-20200214223636-26d376326b75
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/quic-go v0.60.0
	github.com/scionproto/scion v0.15.0
	golang.org/x/sys v0.46.0
	google.golang.org/grpc v1.82.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dchest/cmac v1.0.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.47 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.69.0 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/uber/jaeger-client-go v2.30.0+incompatible // indirect
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/exp v0.0.0-20260611194520-c48552f49976 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260630182238-925bb5da69e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	zgo.at/zcache/v2 v2.4.1 // indirect
)

replace github.com/miscreant/miscreant.go => ./vendor.mod/miscreant.go
