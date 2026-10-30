package server_test

import (
	"testing"
	"time"

	"example.com/scion-time/core/server"

	"example.com/scion-time/net/ntp"
)

func TestSimpleRequest(t *testing.T) {
	server.LogTSS(t, "pre")

	cTxTime := time.Now().UTC()
	ntpreq := ntp.Packet{}
	ntpreq.SetVersion(ntp.VersionMax)
	ntpreq.SetMode(ntp.ModeClient)
	ntpreq.TransmitTime = ntp.Time64FromTime(cTxTime)

	rxt := time.Now().UTC()
	clientID := "client-0"

	txt0 := time.Now().UTC()
	var ntpresp ntp.Packet
	server.HandleRequest(clientID, &ntpreq, &rxt, &txt0, &ntpresp)

	server.LogTSS(t, "post")
}
