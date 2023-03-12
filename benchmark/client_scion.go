package benchmark

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/scion"
	"example.com/scion-time/net/udp"
)

func RunSCIONBenchmark(daemonAddr string, localAddr, remoteAddr *snet.UDPAddr) {
	ctx := context.Background()

	dc, err := daemon.NewService(daemonAddr).Connect(ctx)
	if err != nil {
		log.Fatalf("Failed to create SCION daemon connector: %v", err)
	}

	ps, err := dc.Paths(ctx, remoteAddr.IA, localAddr.IA, daemon.PathReqFlags{Refresh: true})
	if err != nil {
		log.Fatalf("Failed to lookup paths: %v:", err)
	}
	if len(ps) == 0 {
		log.Fatalf("No paths to %v available", remoteAddr.IA)
	}

	log.Printf("Available paths to %v:", remoteAddr.IA)
	for _, p := range ps {
		log.Printf("\t%v", p)
	}

	sp := ps[0]

	log.Printf("Selected path to %v:", remoteAddr.IA)
	log.Printf("\t%v", sp)

	nextHop := sp.UnderlayNextHop()
	if nextHop == nil && remoteAddr.IA.Equal(localAddr.IA) {
		nextHop = &net.UDPAddr{
			IP:   remoteAddr.Host.IP,
			Port: scion.EndhostPort,
			Zone: remoteAddr.Host.Zone,
		}
	}

	// const numClientGoroutine = 8
	// const numRequestPerClient = 10000
	const numClientGoroutine = 1
	const numRequestPerClient = 10000 * 100
	var mu sync.Mutex
	sg := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClientGoroutine)
	for i := numClientGoroutine; i > 0; i-- {
		go func() {
			hg := hdrhistogram.New(1, 50000, 5)

			conn, err := net.DialUDP("udp", localAddr.Host, nextHop)
			if err != nil {
				log.Printf("Failed to dial UDP connection: %v", err)
				return
			}
			defer conn.Close()
			_ = udp.EnableRxTimestamps(conn)

			defer wg.Done()
			<-sg
			for j := numRequestPerClient; j > 0; j-- {
				ntpreq := ntp.Packet{}
				buf := make([]byte, ntp.PacketLen)

				cTxTime := timebase.Now()

				ntpreq.SetVersion(ntp.VersionMax)
				ntpreq.SetMode(ntp.ModeClient)
				ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime)
				ntp.EncodePacket(&buf, &ntpreq)

				pkt := &snet.Packet{
					PacketInfo: snet.PacketInfo{
						Source: snet.SCIONAddress{
							IA:   localAddr.IA,
							Host: addr.HostFromIP(localAddr.Host.IP),
						},
						Destination: snet.SCIONAddress{
							IA:   remoteAddr.IA,
							Host: addr.HostFromIP(remoteAddr.Host.IP),
						},
						Path: sp.Dataplane(),
						Payload: snet.UDPPayload{
							SrcPort: uint16(localAddr.Host.Port),
							DstPort: uint16(remoteAddr.Host.Port),
							Payload: buf,
						},
					},
				}

				err = pkt.Serialize()
				if err != nil {
					log.Printf("Failed to serialize packet: %v", err)
					return
				}

				_, err = conn.Write(pkt.Bytes)
				if err != nil {
					log.Printf("Failed to write packet: %v", err)
					return
				}

				pkt.Prepare()
				oob := make([]byte, udp.TimestampLen())

				n, oobn, flags, _, err := conn.ReadMsgUDPAddrPort(pkt.Bytes, oob)
				if err != nil {
					log.Printf("Failed to read packet: %v", err)
					return
				}
				if flags != 0 {
					log.Printf("Failed to read packet, flags: %v", flags)
					return
				}

				oob = oob[:oobn]
				cRxTime, err := udp.TimestampFromOOBData(oob)
				if err != nil {
					cRxTime = timebase.Now()
					log.Printf("Failed to read packet timestamp")
				}
				pkt.Bytes = pkt.Bytes[:n]

				err = pkt.Decode()
				if err != nil {
					log.Printf("Failed to decode packet: %v", err)
					return
				}

				udppkt, ok := pkt.Payload.(snet.UDPPayload)
				if !ok {
					log.Printf("Failed to read packet payload: not a UDP packet")
					return
				}

				var ntpresp ntp.Packet
				err = ntp.DecodePacket(&ntpresp, udppkt.Payload, nil)
				if err != nil {
					log.Printf("Failed to decode packet payload: %v", err)
					return
				}

				if ntpresp.OriginTime != ntp.Time64FromTime(cTxTime) {
					log.Printf("Unrelated packet received")
					return
				}

				err = ntp.ValidateResponseMetadata(&ntpresp)
				if err != nil {
					log.Printf("Unexpected packet received: %v", err)
					return
				}

				sRxTime := ntp.TimeFromTime64(ntpresp.ReceiveTime)
				sTxTime := ntp.TimeFromTime64(ntpresp.TransmitTime)

				err = ntp.ValidateResponseTimestamps(cTxTime, sRxTime, sTxTime, cRxTime)
				if err != nil {
					log.Printf("Unexpected packet received: %v", err)
					return
				}

				_ = ntp.ClockOffset(cTxTime, sRxTime, sTxTime, cRxTime)
				roundTripDelay := ntp.RoundTripDelay(cTxTime, sRxTime, sTxTime, cRxTime)

				err = hg.RecordValue(roundTripDelay.Microseconds())
				if err != nil {
					log.Printf("Failed to record histogram value: %v", err)
					return
				}
			}
			mu.Lock()
			defer mu.Unlock()
			hg.PercentilesPrint(os.Stdout, 1, 1.0)
		}()
	}
	t0 := time.Now()
	close(sg)
	wg.Wait()
	log.Print(time.Since(t0))
}
