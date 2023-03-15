package scion

import (
	"github.com/scionproto/scion/pkg/slayers"
)

const (
	DRKeyTypeHostHost          = 1
	DRKeyDirectionSenderSide   = 0
	DRKeyDirectionReceiverSide = 1
	DRKeyProtoIdTS             = 123

	PacketAuthMetadataLen = 12
	PacketAuthMACLen      = 16
	PacketAuthOptDataLen  = PacketAuthMetadataLen + PacketAuthMACLen

	PacketAuthSPIClient = uint32(DRKeyTypeHostHost)<<17 |
		uint32(DRKeyDirectionReceiverSide)<<16 |
		uint32(DRKeyProtoIdTS)
	PacketAuthSPIServer = uint32(DRKeyTypeHostHost)<<17 |
		uint32(DRKeyDirectionSenderSide)<<16 |
		uint32(DRKeyProtoIdTS)
	PacketAuthAlgorithm = uint8(0) // AES-CMAC
)

func PreparePacketAuthOpt(authOpt *slayers.EndToEndOption, spi uint32, algo uint8) {
	authOptData := authOpt.OptData
	authOptData[0] = byte(spi >> 24)
	authOptData[1] = byte(spi >> 16)
	authOptData[2] = byte(spi >> 8)
	authOptData[3] = byte(spi)
	authOptData[4] = byte(algo)
	// TODO: Timestamp and Sequence Number
	// See https://github.com/scionproto/scion/pull/4300
	authOptData[5], authOptData[6], authOptData[7] = 0, 0, 0
	authOptData[8], authOptData[9], authOptData[10], authOptData[11] = 0, 0, 0, 0
	// Authenticator
	authOptData[12], authOptData[13], authOptData[14], authOptData[15] = 0, 0, 0, 0
	authOptData[16], authOptData[17], authOptData[18], authOptData[19] = 0, 0, 0, 0
	authOptData[20], authOptData[21], authOptData[22], authOptData[23] = 0, 0, 0, 0
	authOptData[24], authOptData[25], authOptData[26], authOptData[27] = 0, 0, 0, 0

	authOpt.OptType = slayers.OptTypeAuthenticator
	authOpt.OptData = authOptData
	authOpt.OptAlign[0] = 4
	authOpt.OptAlign[1] = 2
	authOpt.OptDataLen = 0
	authOpt.ActualLength = 0
}
