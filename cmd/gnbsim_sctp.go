// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.
package main

import (
	"fmt"
	"github.com/ishidawataru/sctp"
	"net"
	"time"
)

const recvTimer = 5 // sec

func newN2Conn(amfAddr net.IPAddr, amfPort int) (
	conn *sctp.SCTPConn, info *sctp.SndRcvInfo, err error) {

	ips := []net.IPAddr{amfAddr}
	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    amfPort,
	}

	t := time.Duration(recvTimer)
	c := make(chan bool, 1)
	go func() {
		conn, err = sctp.DialSCTP("sctp", nil, addr)
		if err != nil {
			err = fmt.Errorf("failed to sctp dial: %s", err)
			return
		}
		c <- true
	}()
	select {
	case <-c:
		break
	case <-time.After(t * time.Second):
		err = fmt.Errorf("sctp dial timeout (%d sec)", t)
		return
	}

	info = &sctp.SndRcvInfo{
		Stream: 0,
		PPID:   0x3c000000, // Paylod Protocol Identifier: NGAP(60)
	}
	conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)
	return
}

func (s *GnbsimSession) send(pdu []byte) {

	_, err := s.n1conn.SCTPWrite(pdu, s.n1info)
	if err != nil {
		err = fmt.Errorf("failed to sctp send: %s", err)
	}
	return
}

func (s *GnbsimSession) recv(t time.Duration) (err error) {

	if t == 0 {
		t = recvTimer
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
		err = fmt.Errorf("sctp read timeout (%d sec)", t)
		break
	}
	return
}
