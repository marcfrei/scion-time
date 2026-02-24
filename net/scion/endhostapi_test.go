package scion

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/VictoriaMetrics/easyproto"

	"github.com/scionproto/scion/pkg/addr"
)

func TestBuildUnderlayState(t *testing.T) {
	local := addr.MustParseIA("64-2:0:9")
	routers := []underlayRouter{
		{
			isdAs:      local,
			address:    "192.0.2.10:30041",
			interfaces: []uint32{11, 12},
		},
		{
			isdAs:      local,
			address:    "192.0.2.11:30041",
			interfaces: []uint32{13},
		},
	}

	gotIA, gotNextHop, err := buildUnderlayState(routers)
	if err != nil {
		t.Fatalf("buildUnderlayState() error = %v", err)
	}
	if gotIA != local {
		t.Fatalf("local IA = %v, want %v", gotIA, local)
	}
	if got, want := len(gotNextHop), 3; got != want {
		t.Fatalf("next-hop map size = %d, want %d", got, want)
	}
	if got, want := gotNextHop[11].String(), "192.0.2.10:30041"; got != want {
		t.Fatalf("ifID 11 next-hop = %q, want %q", got, want)
	}
	if got, want := gotNextHop[13].String(), "192.0.2.11:30041"; got != want {
		t.Fatalf("ifID 13 next-hop = %q, want %q", got, want)
	}
}

func TestBuildUnderlayStateAmbiguousIA(t *testing.T) {
	routers := []underlayRouter{
		{
			isdAs:      addr.MustParseIA("64-2:0:9"),
			address:    "192.0.2.10:30041",
			interfaces: []uint32{11},
		},
		{
			isdAs:      addr.MustParseIA("64-2:0:10"),
			address:    "192.0.2.11:30041",
			interfaces: []uint32{12},
		},
	}
	_, _, err := buildUnderlayState(routers)
	if err == nil {
		t.Fatalf("buildUnderlayState() unexpectedly succeeded")
	}
}

func TestDecodeListUnderlaysRouters(t *testing.T) {
	local := addr.MustParseIA("64-2:0:9")
	raw := encodeUnderlaysResponsePB([]underlayRouter{
		{
			isdAs:      local,
			address:    "192.0.2.10:30041",
			interfaces: []uint32{11, 12},
		},
	})
	routers, err := decodeListUnderlaysRouters(raw)
	if err != nil {
		t.Fatalf("decodeListUnderlaysRouters() error = %v", err)
	}
	if got, want := len(routers), 1; got != want {
		t.Fatalf("router count = %d, want %d", got, want)
	}
	if got, want := routers[0].isdAs, local; got != want {
		t.Fatalf("router IA = %v, want %v", got, want)
	}
	if got, want := routers[0].address, "192.0.2.10:30041"; got != want {
		t.Fatalf("router address = %q, want %q", got, want)
	}
}

func TestEndhostAPIControlPlaneFetchPathsEmptyResponse(t *testing.T) {
	local := addr.MustParseIA("64-2:0:9")
	dst := addr.MustParseIA("71-ff00:0:114")
	var reqCount int
	cp := &endhostAPIControlPlane{
		localIA:      local,
		ifNextHop:    map[uint16]*net.UDPAddr{11: {IP: []byte{192, 0, 2, 10}, Port: 30041}},
		listPathsURL: "http://ehapi.invalid/" + endhostMethodListPaths,
		client: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				reqCount++
				if got, want := r.Method, http.MethodPost; got != want {
					t.Errorf("method = %q, want %q", got, want)
				}
				if got, want := r.Header.Get("Content-Type"), endhostContentType; got != want {
					t.Errorf("content-type = %q, want %q", got, want)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatalf("read request body: %v", err)
				}
				gotSrc, gotDst, gotToken, err := decodeListPathsRequestForTest(body)
				if err != nil {
					t.Fatalf("decode list paths request: %v", err)
				}
				if gotSrc != local || gotDst != dst {
					t.Fatalf("request src,dst = %v,%v, want %v,%v", gotSrc, gotDst, local, dst)
				}
				if gotToken != "" {
					t.Fatalf("unexpected pagination token %q", gotToken)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}),
		},
	}

	paths, err := cp.FetchPaths(context.Background(), dst)
	if err != nil {
		t.Fatalf("FetchPaths() error = %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("FetchPaths() path count = %d, want 0", len(paths))
	}
	if got, want := reqCount, 1; got != want {
		t.Fatalf("path request count = %d, want %d", got, want)
	}
}

func TestEndhostAPIConnectorConnectInvalidAddress(t *testing.T) {
	_, err := EndhostAPIConnector{Address: "://bad-url"}.Connect(context.Background())
	if err == nil {
		t.Fatalf("Connect() unexpectedly succeeded")
	}
}

func encodeUnderlaysResponsePB(routers []underlayRouter) []byte {
	var m easyproto.Marshaler
	mm := m.MessageMarshaler()
	udp := mm.AppendMessage(1)
	for _, router := range routers {
		r := udp.AppendMessage(1)
		r.AppendUint64(1, uint64(router.isdAs))
		r.AppendString(2, router.address)
		if len(router.interfaces) > 0 {
			r.AppendUint32s(3, router.interfaces)
		}
	}
	return m.Marshal(nil)
}

func decodeListPathsRequestForTest(src []byte) (sourceIA, destinationIA addr.IA, pageToken string, err error) {
	var fc easyproto.FieldContext
	for len(src) > 0 {
		src, err = fc.NextField(src)
		if err != nil {
			return 0, 0, "", err
		}
		switch fc.FieldNum {
		case 1:
			if v, ok := fc.Uint64(); ok {
				sourceIA = addr.IA(v)
			}
		case 2:
			if v, ok := fc.Uint64(); ok {
				destinationIA = addr.IA(v)
			}
		case 4:
			if v, ok := fc.String(); ok {
				pageToken = v
			}
		}
	}
	if sourceIA == 0 || destinationIA == 0 {
		return 0, 0, "", fmt.Errorf("missing src/dst IA in request")
	}
	return sourceIA, destinationIA, pageToken, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
