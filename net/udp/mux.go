package udp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
)

const rxQueueLen = 64

type UDPMuxConn struct {
	state   *muxState
	mu      sync.Mutex
	readDL  time.Time
	writeDL time.Time
	dscp    uint8
	closed  bool
	rx      struct {
		enabled bool
		pktCh   chan UDPMuxPacket
		sigCh   chan struct{}
	}
	tx struct {
		mu          sync.Mutex
		enabled     bool
		nextIDWrite uint32
		pending     map[uint32]uint32
	}
}

type muxState struct {
	shared         bool
	raw            *net.UDPConn
	rawMu          sync.Mutex
	defaultReadDL  time.Time
	defaultWriteDL time.Time
	defaultDSCP    uint8
	rx             struct {
		mu      sync.Mutex
		running bool
		conns   []rxConn
		err     error
	}
	tx struct {
		mu          sync.Mutex
		readMu      sync.Mutex
		enabled     bool
		iface       string
		index       int
		nextIDWrite uint32
		nextIDRead  uint32
		pending     map[uint32]bool
		results     map[uint32]time.Time
	}
}

type rxConn struct {
	conn    *UDPMuxConn
	matcher UDPMuxMatcher
}

type UDPMuxPacket struct {
	Data  []byte
	OOB   []byte
	Flags int
	Addr  netip.AddrPort
}

type UDPMuxMatcher func(UDPMuxPacket) bool

var (
	muxStateReg struct {
		mu     sync.Mutex
		states map[string]*muxState
	}

	errMissingReadMatcher = errors.New("missing UDP mux read matcher")
	errTimestampingConfig = errors.New("UDP mux timestamping configuration mismatch")
)

func newUDPMuxConn(state *muxState) *UDPMuxConn {
	conn := &UDPMuxConn{
		state:   state,
		readDL:  state.defaultReadDL,
		writeDL: state.defaultWriteDL,
		dscp:    state.defaultDSCP,
	}
	if state.shared {
		conn.rx.pktCh = make(chan UDPMuxPacket, rxQueueLen)
		conn.rx.sigCh = make(chan struct{})
	}
	return conn
}

func OpenUDPMuxConn(ctx context.Context, localAddr *net.UDPAddr) (*UDPMuxConn, error) {
	laddr := muxAddrString(localAddr)

	if localAddr.Port == 0 {
		var lc net.ListenConfig
		pconn, err := lc.ListenPacket(ctx, "udp", laddr)
		if err != nil {
			return nil, err
		}
		return newUDPMuxConn(&muxState{
			raw: pconn.(*net.UDPConn),
		}), nil
	}

	muxStateReg.mu.Lock()
	defer muxStateReg.mu.Unlock()
	if muxStateReg.states == nil {
		muxStateReg.states = make(map[string]*muxState)
	}
	state := muxStateReg.states[laddr]
	if state != nil {
		state.rx.mu.Lock()
		failed := state.rx.err != nil
		state.rx.mu.Unlock()
		if failed {
			delete(muxStateReg.states, laddr)
			state = nil
		}
	}
	if state == nil {
		var lc net.ListenConfig
		pconn, err := lc.ListenPacket(ctx, "udp", laddr)
		if err != nil {
			return nil, err
		}
		raw := pconn.(*net.UDPConn)
		dscp, err := getDSCP(raw)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		state = &muxState{
			shared:      true,
			raw:         raw,
			defaultDSCP: dscp,
		}
		muxStateReg.states[laddr] = state
	}
	return newUDPMuxConn(state), nil
}

func muxAddrString(addr *net.UDPAddr) string {
	if addr != nil && addr.IP.To4() != nil && addr.Zone != "" {
		addr = &net.UDPAddr{
			IP:   addr.IP,
			Port: addr.Port,
		}
	}
	return addr.String()
}

func (c *UDPMuxConn) Close() error {
	if !c.state.shared {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		return c.state.raw.Close()
	}

	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.rx.sigCh)
		c.rx.sigCh = make(chan struct{})
	}
	c.mu.Unlock()

	c.state.rx.mu.Lock()
	c.state.rx.conns = slices.DeleteFunc(c.state.rx.conns, func(rc rxConn) bool {
		return rc.conn == c
	})
	c.state.rx.mu.Unlock()

	c.state.rawMu.Lock()
	defer c.state.rawMu.Unlock()
	c.state.tx.mu.Lock()
	c.tx.mu.Lock()
	for localID, rawID := range c.tx.pending {
		delete(c.state.tx.pending, rawID)
		delete(c.state.tx.results, rawID)
		delete(c.tx.pending, localID)
	}
	c.tx.mu.Unlock()
	c.state.tx.mu.Unlock()

	return nil
}

func (c *UDPMuxConn) SetReadMatcher(m UDPMuxMatcher) {
	if m == nil {
		panic("unexpected UDP mux read matcher: nil")
	}
	if !c.state.shared {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	if c.rx.enabled {
		panic("unexpected UDP mux read matcher: already set")
	}
	c.rx.enabled = true
	s := c.state
	s.rx.mu.Lock()
	defer s.rx.mu.Unlock()
	s.rx.conns = append(s.rx.conns, rxConn{conn: c, matcher: m})
	if !s.rx.running && s.rx.err == nil {
		s.rx.running = true
		go s.runReader()
	}
}

func (c *UDPMuxConn) read() (UDPMuxPacket, error) {
	for {
		c.mu.Lock()
		closed := c.closed
		enabled := c.rx.enabled
		readDL := c.readDL
		sigCh := c.rx.sigCh
		c.mu.Unlock()
		if closed {
			return UDPMuxPacket{}, net.ErrClosed
		}
		if !enabled {
			return UDPMuxPacket{}, errMissingReadMatcher
		}
		c.state.rx.mu.Lock()
		rxErr := c.state.rx.err
		c.state.rx.mu.Unlock()
		if rxErr != nil {
			return UDPMuxPacket{}, rxErr
		}
		var timerCh <-chan time.Time
		if !readDL.IsZero() {
			timeout := time.Until(readDL)
			if timeout <= 0 {
				return UDPMuxPacket{}, os.ErrDeadlineExceeded
			}
			timerCh = time.After(timeout)
		}
		select {
		case pkt := <-c.rx.pktCh:
			return pkt, nil
		case <-sigCh:
			continue
		case <-timerCh:
			return UDPMuxPacket{}, os.ErrDeadlineExceeded
		}
	}
}

func (s *muxState) runReader() {
	buf := make([]byte, 64*1024)
	oob := make([]byte, TimestampLen())
	for {
		n, oobn, flags, addr, err := s.raw.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EBADF) {
				s.rx.mu.Lock()
				s.rx.running = false
				s.rx.err = net.ErrClosed
				rxConns := slices.Clone(s.rx.conns)
				s.rx.mu.Unlock()
				for _, c := range rxConns {
					c.conn.mu.Lock()
					close(c.conn.rx.sigCh)
					c.conn.rx.sigCh = make(chan struct{})
					c.conn.mu.Unlock()
				}
				return
			}
			time.Sleep(time.Millisecond)
			continue
		}
		pkt := UDPMuxPacket{
			Data:  buf[:n],
			OOB:   oob[:oobn],
			Flags: flags,
			Addr:  addr,
		}
		s.rx.mu.Lock()
		rxConns := slices.Clone(s.rx.conns)
		s.rx.mu.Unlock()
		for _, c := range rxConns {
			if c.matcher(pkt) {
				pkt.Data = bytes.Clone(pkt.Data)
				pkt.OOB = bytes.Clone(pkt.OOB)
				c.conn.enqueue(pkt)
				break
			}
		}
	}
}

func (c *UDPMuxConn) enqueue(pkt UDPMuxPacket) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return
	}
	select {
	case c.rx.pktCh <- pkt:
	default:
	}
}

func (c *UDPMuxConn) LocalAddr() net.Addr {
	return c.state.raw.LocalAddr()
}

func (c *UDPMuxConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if !c.state.shared {
		return c.state.raw.ReadFrom(b)
	}
	pkt, err := c.read()
	if err != nil {
		return 0, nil, err
	}
	n := copy(b, pkt.Data)
	return n, net.UDPAddrFromAddrPort(pkt.Addr), nil
}

func (c *UDPMuxConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	if !c.state.shared {
		return c.state.raw.ReadFromUDPAddrPort(b)
	}
	pkt, err := c.read()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n := copy(b, pkt.Data)
	return n, pkt.Addr, nil
}

func (c *UDPMuxConn) ReadMsgUDPAddrPort(b, oob []byte) (int, int, int, netip.AddrPort, error) {
	if !c.state.shared {
		return c.state.raw.ReadMsgUDPAddrPort(b, oob)
	}
	pkt, err := c.read()
	if err != nil {
		return 0, 0, 0, netip.AddrPort{}, err
	}
	n := copy(b, pkt.Data)
	oobn := copy(oob, pkt.OOB)
	flags := pkt.Flags
	if n < len(pkt.Data) {
		flags |= syscall.MSG_TRUNC
	}
	if oobn < len(pkt.OOB) {
		flags |= syscall.MSG_CTRUNC
	}
	return n, oobn, flags, pkt.Addr, nil
}

func (c *UDPMuxConn) SetDeadline(t time.Time) error {
	if !c.state.shared {
		return c.state.raw.SetDeadline(t)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDL = t
	c.writeDL = t
	close(c.rx.sigCh)
	c.rx.sigCh = make(chan struct{})
	return nil
}

func (c *UDPMuxConn) SetReadDeadline(t time.Time) error {
	if !c.state.shared {
		return c.state.raw.SetReadDeadline(t)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDL = t
	close(c.rx.sigCh)
	c.rx.sigCh = make(chan struct{})
	return nil
}

func (c *UDPMuxConn) SetWriteDeadline(t time.Time) error {
	if !c.state.shared {
		return c.state.raw.SetWriteDeadline(t)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDL = t
	return nil
}

func (c *UDPMuxConn) SyscallConn() (syscall.RawConn, error) {
	return c.state.raw.SyscallConn()
}

func (c *UDPMuxConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if !c.state.shared {
		return c.state.raw.WriteTo(b, addr)
	}
	c.state.rawMu.Lock()
	defer c.state.rawMu.Unlock()
	if err := c.prepareWrite(); err != nil {
		return 0, err
	}
	n, err := c.state.raw.WriteTo(b, addr)
	if err == nil {
		c.recordWrite()
	}
	return n, err
}

func (c *UDPMuxConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if !c.state.shared {
		return c.state.raw.WriteToUDPAddrPort(b, addr)
	}
	c.state.rawMu.Lock()
	defer c.state.rawMu.Unlock()
	if err := c.prepareWrite(); err != nil {
		return 0, err
	}
	n, err := c.state.raw.WriteToUDPAddrPort(b, addr)
	if err == nil {
		c.recordWrite()
	}
	return n, err
}

func (c *UDPMuxConn) prepareWrite() error {
	c.mu.Lock()
	closed := c.closed
	writeDL := c.writeDL
	dscp := c.dscp
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	_ = setDSCP(c.state.raw, dscp)
	return c.state.raw.SetWriteDeadline(writeDL)
}

func (c *UDPMuxConn) recordWrite() {
	c.state.tx.mu.Lock()
	defer c.state.tx.mu.Unlock()
	c.tx.mu.Lock()
	defer c.tx.mu.Unlock()

	if !c.state.tx.enabled {
		return
	}
	rawID := c.state.tx.nextIDWrite
	c.state.tx.nextIDWrite++

	if !c.tx.enabled {
		return
	}
	localID := c.tx.nextIDWrite
	c.tx.nextIDWrite++

	c.state.tx.pending[rawID] = true
	c.tx.pending[localID] = rawID
}

func (c *UDPMuxConn) enableTimestamping(iface string, index int) error {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if !c.state.shared {
		return enableTimestamping(c.state.raw, iface, index)
	}
	c.state.rawMu.Lock()
	defer c.state.rawMu.Unlock()
	c.state.tx.mu.Lock()
	defer c.state.tx.mu.Unlock()
	c.tx.mu.Lock()
	defer c.tx.mu.Unlock()

	if c.state.tx.enabled {
		if c.state.tx.iface != iface || c.state.tx.index != index {
			return errTimestampingConfig
		}
	} else {
		err := enableTimestamping(c.state.raw, iface, index)
		if err != nil {
			return err
		}
		c.state.tx.enabled = true
		c.state.tx.iface = iface
		c.state.tx.index = index
		c.state.tx.pending = make(map[uint32]bool)
		c.state.tx.results = make(map[uint32]time.Time)
	}
	if !c.tx.enabled {
		c.tx.enabled = true
		c.tx.pending = make(map[uint32]uint32)
	}
	return nil
}

func (c *UDPMuxConn) setDSCP(dscp uint8) error {
	if !c.state.shared {
		return setDSCP(c.state.raw, dscp)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dscp = dscp
	return nil
}

func (c *UDPMuxConn) readTXTimestamp(minLocalID uint32) (time.Time, uint32, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return time.Time{}, 0, net.ErrClosed
	}
	if !c.state.shared {
		return readTXTimestamp(c.state.raw, minLocalID, nil)
	}
	var minRawID uint32
	var minRawIDSet bool
	for {
		localID, rawID, ok := c.popTX(minLocalID, minRawID, minRawIDSet)
		if !ok {
			return time.Time{}, 0, errTimestampNotFound
		}
		ts, nextRawID, err := c.state.readRawTXTimestamp(rawID)
		if err == nil {
			return ts, localID, nil
		}
		if err != errTimestampNotFound {
			return time.Time{}, 0, err
		}
		minLocalID = localID + 1
		minRawID = nextRawID
		minRawIDSet = true
	}
}

func (c *UDPMuxConn) popTX(id, minRawID uint32, minRawIDSet bool) (uint32, uint32, bool) {
	c.tx.mu.Lock()
	defer c.tx.mu.Unlock()

	var ok bool
	var localID, rawID uint32
	for nextLocalID, nextRawID := range c.tx.pending {
		if seqLess(nextLocalID, id) {
			continue
		}
		if minRawIDSet && seqLess(nextRawID, minRawID) {
			delete(c.tx.pending, nextLocalID)
			continue
		}
		if !ok || seqLess(nextLocalID, localID) {
			localID = nextLocalID
			rawID = nextRawID
			ok = true
		}
	}
	if ok {
		delete(c.tx.pending, localID)
	}
	return localID, rawID, ok
}

func (s *muxState) readRawTXTimestamp(rawID uint32) (time.Time, uint32, error) {
	s.tx.readMu.Lock()
	defer s.tx.readMu.Unlock()

	for {
		s.tx.mu.Lock()
		if ts, ok := s.tx.results[rawID]; ok {
			delete(s.tx.results, rawID)
			delete(s.tx.pending, rawID)
			s.tx.mu.Unlock()
			return ts, rawID, nil
		}
		if seqLess(rawID, s.tx.nextIDRead) {
			nextIDRead := s.tx.nextIDRead
			delete(s.tx.pending, rawID)
			s.tx.mu.Unlock()
			return time.Time{}, nextIDRead, errTimestampNotFound
		}
		nextIDRead := s.tx.nextIDRead
		s.tx.mu.Unlock()

		ts, rawIDRead, err := readTXTimestamp(s.raw, nextIDRead, &s.rawMu)
		if err != nil {
			if err == errTimestampNotFound {
				s.tx.mu.Lock()
				delete(s.tx.pending, rawID)
				s.tx.mu.Unlock()
				return time.Time{}, rawID + 1, err
			}
			return time.Time{}, 0, err
		}
		s.tx.mu.Lock()
		for id := range s.tx.pending {
			if seqLess(id, rawIDRead) {
				delete(s.tx.pending, id)
			}
		}
		s.tx.nextIDRead = rawIDRead + 1
		if rawIDRead != rawID {
			if s.tx.pending[rawIDRead] {
				s.tx.results[rawIDRead] = ts
			}
		}
		delete(s.tx.pending, rawIDRead)
		s.tx.mu.Unlock()

		if seqLess(rawID, rawIDRead) {
			return time.Time{}, rawIDRead, errTimestampNotFound
		}
		if rawIDRead == rawID {
			return ts, rawIDRead, nil
		}
	}
}
