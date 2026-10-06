package client

import (
	"errors"
)

var (
	errWrite                  = errors.New("failed to write packet")
	errUnexpectedPacketFlags  = errors.New("failed to read packet: unexpected flags")
	errUnexpectedPacketSource = errors.New("failed to read packet: unexpected source")
	errUnexpectedPacket       = errors.New("failed to read packet: unexpected type or structure")
	errUnexpectedSequenceID   = errors.New("failed to read packet: unexpected sequence ID")

	errInvalidPacketAuthenticator = errors.New("invalid authenticator")
)
