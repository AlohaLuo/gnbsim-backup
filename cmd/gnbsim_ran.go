// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.
package main

import (
	"net"
)

func (s *GnbsimSession) InitRAN() (err error) {

	const amfPort = 38412
	amfAddr, _ := net.ResolveIPAddr("ip", s.gnb.NGAPPeerAddr)

	s.n1conn, s.n1info, err = NewN2Conn(*amfAddr, amfPort)
	if err != nil {
		return
	}

	pdu := s.gnb.MakeNGSetupRequest()
	s.Send(pdu)
	s.Recv(0)

	return
}
