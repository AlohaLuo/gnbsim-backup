package main

import (
	"fmt"
	"net"
	"github.com/ishidawataru/sctp"
)

func NewN2Conn(amfAddr net.IPAddr, amfPort int) (
	conn *sctp.SCTPConn, info *sctp.SndRcvInfo, err error) {

	ips := []net.IPAddr{amfAddr}
	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    amfPort,
	}

	conn, err = sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		err = fmt.Errorf("failed to sctp dial: %s", err)
		return
	}

	info = &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   0x3c000000, // Paylod Protocol Identifier: NGAP(60)
	}

	conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)

	return
}
