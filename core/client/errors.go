package client

import (
	"errors"
)

var (
	errWrite                  = errors.New("failed to write packet")
	errUnexpectedPacketFlags  = errors.New("failed to read packet: unexpected flags")
	errUnexpectedPacketSource = errors.New("failed to read packet: unexpected source")
	errUnexpectedPacket       = errors.New("failed to read packet: unexpected type or structure")

	errInvalidPacketAuthenticator = errors.New("invalid authenticator")
	errUnusableTimestamps         = errors.New("unusable packet timestamps")

	errFilterPending  = errors.New("lucky packet pending: more samples needed")
	errFilterRejected = errors.New("lucky packet rejected: round trip delay out of range")
)
