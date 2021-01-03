package main

import (
	"fmt"
	"net"
	"time"
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

func (s *GnbsimSession) Send(pdu []byte) {

	_, err := s.n1conn.SCTPWrite(pdu, s.n1info)
	if err != nil {
		err = fmt.Errorf("failed to sctp send: %s", err)
	}
	return
}

func (s *GnbsimSession) Recv(t time.Duration) (err error) {

	const defaultTimer = 5 // sec

	if t == 0 {
		t = defaultTimer
	}

	c := make(chan bool, 1)
	go func() {
		buf := make([]byte, 1500)
		n, info, err := s.n1conn.SCTPRead(buf)
		s.n1info = info

		if err != nil {
			err = fmt.Errorf("failed to sctp read: %s", err)
			c <- true
			return
		}

		buf = buf[:n]
		fmt.Printf("dump: %x\n", buf)
		s.gnb.Decode(&buf)
		c <- true
	}()
	select {
	case <-c:
		break
	case <-time.After(t * time.Second):
		err = fmt.Errorf("sctp read timeout(%d sec)", t)
		break
	}
	return
}


