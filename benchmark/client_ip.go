package benchmark

import (
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"

	"example.com/scion-time/core/timebase"

	"example.com/scion-time/net/ntp"
	"example.com/scion-time/net/udp"
)

func RunIPBenchmark(localAddr, remoteAddr *net.UDPAddr) {
	// const numClientGoroutine = 8
	// const numRequestPerClient = 10000
	const numClientGoroutine = 1
	const numRequestPerClient = 1_000_000
	var mu sync.Mutex
	sg := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(numClientGoroutine)
	for i := numClientGoroutine; i > 0; i-- {
		go func() {
			hg := hdrhistogram.New(1, 50000, 5)

			conn, err := net.DialUDP("udp", localAddr, remoteAddr)
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

				_, err = conn.Write(buf)
				if err != nil {
					log.Printf("Failed to write packet: %v", err)
					return
				}

				oob := make([]byte, udp.TimestampLen())

				n, oobn, flags, _, err := conn.ReadMsgUDPAddrPort(buf, oob)
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
				buf = buf[:n]

				var ntpresp ntp.Packet
				err = ntp.DecodePacket(&ntpresp, buf, nil, nil)
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
