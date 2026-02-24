package scion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/VictoriaMetrics/easyproto"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/segment"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/path/combinator"
)

const (
	endhostMethodListUnderlays = "scion.endhost.v1.UnderlayService/ListUnderlays"
	endhostMethodListPaths     = "scion.endhost.v1.PathService/ListPaths"

	endhostContentType = "application/proto"
	maxErrorBody       = 8192
	maxListPathsPages  = 64
)

var (
	endhostAPIMarshalerPool easyproto.MarshalerPool
)

type connectWireError struct {
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Detail  json.RawMessage `json:"detail,omitempty"`
}

type connectError struct {
	HTTPStatus int
	Code       string
	Message    string
	Body       string
}

func (e *connectError) Error() string {
	if e.Code != "" {
		if e.Message == "" {
			return fmt.Sprintf("connect error: %s", e.Code)
		}
		return fmt.Sprintf("connect error: %s: %s", e.Code, e.Message)
	}
	if e.Message != "" {
		return fmt.Sprintf("http %d: %s", e.HTTPStatus, e.Message)
	}
	if e.Body != "" {
		return fmt.Sprintf("http %d: %s", e.HTTPStatus, e.Body)
	}
	return fmt.Sprintf("http %d", e.HTTPStatus)
}

type endhostAPIControlPlane struct {
	localIA   addr.IA
	ifNextHop map[uint16]*net.UDPAddr

	listUnderlaysURL string
	listPathsURL     string

	client    *http.Client
	transport *http.Transport
}

func (cp *endhostAPIControlPlane) LocalIA(ctx context.Context) (addr.IA, error) {
	return cp.localIA, nil
}

func (cp *endhostAPIControlPlane) FetchPaths(ctx context.Context, dst addr.IA) ([]snet.Path, error) {
	if dst.IsWildcard() {
		panic("wildcard destination is not supported")
	}
	if dst == cp.localIA {
		panic("local-AS destination is not supported")
	}

	var (
		ups   []*segment.PathSegment
		downs []*segment.PathSegment
		cores []*segment.PathSegment

		pageToken string
	)

	for page := range maxListPathsPages {
		req := encodeListPathsRequest(cp.localIA, dst, 0, pageToken)
		resp, err := cp.do(ctx, cp.listPathsURL, req)
		if err != nil {
			return nil, err
		}
		pageUps, pageDowns, pageCores, nextToken, err := decodeListPathsResponse(resp)
		if err != nil {
			return nil, err
		}
		ups = append(ups, pageUps...)
		downs = append(downs, pageDowns...)
		cores = append(cores, pageCores...)

		if nextToken == "" {
			break
		}
		pageToken = nextToken
		if page == maxListPathsPages-1 {
			return nil, errors.New("list paths pagination exceeded limit")
		}
	}

	cpaths := combinator.Combine(cp.localIA, dst, ups, cores, downs, false /* findAllIdentical */)
	spaths := cp.convertPaths(cpaths)

	return spaths, nil
}

func encodeListPathsRequest(sourceIA, destinationIA addr.IA, pageSize int32, pageToken string) []byte {
	m := endhostAPIMarshalerPool.Get()
	defer endhostAPIMarshalerPool.Put(m)
	mm := m.MessageMarshaler()
	mm.AppendUint64(1, uint64(sourceIA))
	mm.AppendUint64(2, uint64(destinationIA))
	if pageSize != 0 {
		mm.AppendInt32(3, pageSize)
	}
	if pageToken != "" {
		mm.AppendString(4, pageToken)
	}
	out := m.Marshal(nil)
	return out
}

func decodeListPathsResponse(src []byte) (
	ups, downs, cores []*segment.PathSegment, nextPageToken string, err error,
) {
	var fc easyproto.FieldContext
	for len(src) > 0 {
		src, err = fc.NextField(src)
		if err != nil {
			return nil, nil, nil, "", err
		}
		switch fc.FieldNum {
		case 1:
			seg, ok := fc.MessageData()
			if !ok {
				return nil, nil, nil, "", fmt.Errorf("invalid ListPathsResponse.up_segments field")
			}
			pathSegment, err := decodePathSegment(seg)
			if err != nil {
				return nil, nil, nil, "", err
			}
			ups = append(ups, pathSegment)
		case 2:
			seg, ok := fc.MessageData()
			if !ok {
				return nil, nil, nil, "", fmt.Errorf("invalid ListPathsResponse.down_segments field")
			}
			pathSegment, err := decodePathSegment(seg)
			if err != nil {
				return nil, nil, nil, "", err
			}
			downs = append(downs, pathSegment)
		case 3:
			seg, ok := fc.MessageData()
			if !ok {
				return nil, nil, nil, "", fmt.Errorf("invalid ListPathsResponse.core_segments field")
			}
			pathSegment, err := decodePathSegment(seg)
			if err != nil {
				return nil, nil, nil, "", err
			}
			cores = append(cores, pathSegment)
		case 4:
			v, ok := fc.String()
			if ok {
				nextPageToken = v
			}
		}
	}
	return ups, downs, cores, nextPageToken, nil
}

func (cp *endhostAPIControlPlane) convertPaths(cpaths []combinator.Path) []snet.Path {
	var paths []snet.Path
	for _, cpath := range cpaths {
		path, err := cp.convertPath(cpath)
		if err != nil {
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func (cp *endhostAPIControlPlane) convertPath(cpath combinator.Path) (snet.Path, error) {
	if len(cpath.Metadata.Interfaces) == 0 {
		return nil, fmt.Errorf("path has no interfaces")
	}
	firstIF := cpath.Metadata.Interfaces[0]
	nextHop, ok := cp.ifNextHop[uint16(firstIF.ID)]
	if !ok {
		return nil, fmt.Errorf("unable to find next hop address, ifID = %v", firstIF.ID)
	}
	return path.Path{
		Src:           cpath.Metadata.Interfaces[0].IA,
		Dst:           cpath.Metadata.Interfaces[len(cpath.Metadata.Interfaces)-1].IA,
		DataplanePath: cpath.SCIONPath,
		NextHop: &net.UDPAddr{
			IP:   append([]byte(nil), nextHop.IP...),
			Port: nextHop.Port,
			Zone: nextHop.Zone,
		},
		Meta: cpath.Metadata,
	}, nil
}

func (cp *endhostAPIControlPlane) FetchHostASKey(ctx context.Context, meta drkey.HostASMeta) (drkey.HostASKey, error) {
	panic("not yet implemented")
}

func (cp *endhostAPIControlPlane) FetchHostHostKey(ctx context.Context, meta drkey.HostHostMeta) (drkey.HostHostKey, error) {
	panic("not yet implemented")
}

func (cp *endhostAPIControlPlane) Close() error {
	if cp.transport != nil {
		cp.transport.CloseIdleConnections()
	}
	return nil
}

func (cp *endhostAPIControlPlane) do(ctx context.Context, endpoint string, reqProto []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(reqProto))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", endhostContentType)
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := cp.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, decodeHTTPError(resp)
	}
	return io.ReadAll(resp.Body)
}

func decodeHTTPError(resp *http.Response) error {
	lr := io.LimitReader(resp.Body, maxErrorBody)
	data, _ := io.ReadAll(lr)
	var cwe connectWireError
	if err := json.Unmarshal(data, &cwe); err == nil && (cwe.Code != "" || cwe.Message != "") {
		return &connectError{
			HTTPStatus: resp.StatusCode,
			Code:       cwe.Code,
			Message:    cwe.Message,
		}
	}
	body := strings.TrimSpace(string(data))
	if body == "" {
		body = resp.Status
	}
	return &connectError{
		HTTPStatus: resp.StatusCode,
		Message:    resp.Status,
		Body:       body,
	}
}

var _ ControlPlane = (*endhostAPIControlPlane)(nil)

type EndhostAPIConnector struct {
	Address string
}

func (c EndhostAPIConnector) Connect(ctx context.Context) (ControlPlane, error) {
	if c.Address == "" {
		panic("invalid configuration: empty address")
	}

	baseURL, err := url.Parse(strings.TrimSpace(c.Address))
	if err != nil {
		return nil, fmt.Errorf("parse endhost API address: %w", err)
	}
	if baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid endhost API address %q (expected URL with scheme and host)", c.Address)
	}

	transport := &http.Transport{
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	transport.Protocols = protocols

	cp := &endhostAPIControlPlane{
		listUnderlaysURL: rpcURL(baseURL, endhostMethodListUnderlays),
		listPathsURL:     rpcURL(baseURL, endhostMethodListPaths),
		client: &http.Client{
			Transport: transport,
		},
		transport: transport,
	}

	resp, err := cp.do(ctx, cp.listUnderlaysURL, nil)
	if err != nil {
		_ = cp.Close()
		return nil, err
	}
	routers, err := decodeListUnderlaysRouters(resp)
	if err != nil {
		_ = cp.Close()
		return nil, err
	}
	localIA, ifNextHop, err := buildUnderlayState(routers)
	if err != nil {
		_ = cp.Close()
		return nil, err
	}
	cp.localIA = localIA
	cp.ifNextHop = ifNextHop
	return cp, nil
}

func rpcURL(base *url.URL, methodPath string) string {
	rel := &url.URL{Path: strings.TrimPrefix(strings.TrimSpace(methodPath), "/")}
	return base.ResolveReference(rel).String()
}

type underlayRouter struct {
	isdAs      addr.IA
	address    string
	interfaces []uint32
}

func decodeListUnderlaysRouters(src []byte) ([]underlayRouter, error) {
	var (
		routers []underlayRouter
		fc      easyproto.FieldContext
	)
	for len(src) > 0 {
		var err error
		src, err = fc.NextField(src)
		if err != nil {
			return nil, err
		}
		if fc.FieldNum != 1 {
			continue
		}
		udp, ok := fc.MessageData()
		if !ok {
			return nil, fmt.Errorf("invalid ListUnderlaysResponse.udp field")
		}
		udpRouters, err := decodeUDPUnderlayRouters(udp)
		if err != nil {
			return nil, err
		}
		routers = append(routers, udpRouters...)
	}
	return routers, nil
}

func decodeUDPUnderlayRouters(src []byte) ([]underlayRouter, error) {
	var (
		routers []underlayRouter
		fc      easyproto.FieldContext
	)
	for len(src) > 0 {
		var err error
		src, err = fc.NextField(src)
		if err != nil {
			return nil, err
		}
		if fc.FieldNum != 1 {
			continue
		}
		routerRaw, ok := fc.MessageData()
		if !ok {
			return nil, fmt.Errorf("invalid UdpUnderlay.routers field")
		}
		router, err := decodeRouter(routerRaw)
		if err != nil {
			return nil, err
		}
		routers = append(routers, router)
	}
	return routers, nil
}

func decodeRouter(src []byte) (underlayRouter, error) {
	var (
		router underlayRouter
		fc     easyproto.FieldContext
	)
	for len(src) > 0 {
		var err error
		src, err = fc.NextField(src)
		if err != nil {
			return underlayRouter{}, err
		}
		switch fc.FieldNum {
		case 1:
			v, ok := fc.Uint64()
			if ok {
				router.isdAs = addr.IA(v)
			}
		case 2:
			v, ok := fc.String()
			if ok {
				router.address = v
			}
		case 3:
			if packed, ok := fc.UnpackUint32s(nil); ok {
				router.interfaces = append(router.interfaces, packed...)
				continue
			}
			if v, ok := fc.Uint32(); ok {
				router.interfaces = append(router.interfaces, v)
			}
		}
	}
	return router, nil
}

func buildUnderlayState(routers []underlayRouter) (addr.IA, map[uint16]*net.UDPAddr, error) {
	if len(routers) == 0 {
		return 0, nil, errors.New("endhost API returned no UDP underlay routers")
	}

	uniqueIAs := make(map[addr.IA]struct{})
	ifNextHop := make(map[uint16]*net.UDPAddr)
	for _, router := range routers {
		if router.isdAs == 0 {
			continue
		}
		uniqueIAs[router.isdAs] = struct{}{}
		nextHop, err := parseUDPEndpoint(router.address)
		if err != nil {
			return 0, nil, fmt.Errorf("parse underlay router endpoint %q: %w", router.address, err)
		}
		for _, ifID := range router.interfaces {
			if ifID == 0 || ifID > math.MaxUint16 {
				return 0, nil, fmt.Errorf("invalid router interface ID: %d", ifID)
			}
			key := uint16(ifID)
			if existing, ok := ifNextHop[key]; ok {
				if !equalUDPAddr(existing, nextHop) {
					return 0, nil, fmt.Errorf("conflicting next-hop for interface ID %d", ifID)
				}
				continue
			}
			ifNextHop[key] = nextHop
		}
	}

	if len(ifNextHop) == 0 {
		return 0, nil, errors.New("endhost API returned no usable UDP router interfaces")
	}

	if len(uniqueIAs) != 1 {
		return 0, nil, fmt.Errorf("expected exactly one local IA in underlay response, got %d", len(uniqueIAs))
	}
	var localIA addr.IA
	for ia := range uniqueIAs {
		localIA = ia
	}
	return localIA, ifNextHop, nil
}

func parseUDPEndpoint(endpoint string) (*net.UDPAddr, error) {
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return nil, err
	}
	addr := ap.Addr()
	ip := addr.AsSlice()
	return &net.UDPAddr{
		IP:   append([]byte(nil), ip...),
		Port: int(ap.Port()),
		Zone: addr.Zone(),
	}, nil
}

func equalUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Port != b.Port || a.Zone != b.Zone {
		return false
	}
	return a.IP.Equal(b.IP)
}

var _ ControlPlaneConnector = (*EndhostAPIConnector)(nil)
