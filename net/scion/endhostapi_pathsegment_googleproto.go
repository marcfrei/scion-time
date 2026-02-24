//go:build ehapi_googleproto

package scion

import (
	"google.golang.org/protobuf/proto"

	"github.com/scionproto/scion/pkg/proto/control_plane"
	"github.com/scionproto/scion/pkg/segment"
)

func decodePathSegment(raw []byte) (*segment.PathSegment, error) {
	var pb control_plane.PathSegment
	if err := proto.Unmarshal(raw, &pb); err != nil {
		return nil, err
	}
	return segment.SegmentFromPB(&pb)
}
