// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.
package main

import (
	"fmt"
	"github.com/hhorai/gnbsim/encoding/gtp"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"strconv"
)

type GnbsimSession struct {
	n1conn *sctp.SCTPConn
	n1info *sctp.SndRcvInfo
	gnb    *ngap.GNB
	ue     []*nas.UE
	gtpu   *gtp.GTP
}

func main() {

	s := initConfig("gnbsim.json")

	err := s.initRAN()
	if err != nil {
		fmt.Printf("InitRAN failed: %v\n", err)
		return
	}

	err = s.initUEs()
	if err != nil {
		fmt.Printf("InitUEs failed: %v\n", err)
		return
	}

	return
}

func initConfig(jsonFile string) (s *GnbsimSession) {

	var obj GnbsimSession
	s = &obj

	s.gnb = ngap.NewNGAP(jsonFile)
	imeisv, _ := strconv.ParseUint(s.gnb.UE.IMEISV, 10, 64)
	msin, _ := strconv.ParseUint(s.gnb.UE.MSIN, 10, 64)

	for i := 0; i < s.gnb.UE.Number; i++ {
		ue := s.gnb.UE
		ue.IMEISV = fmt.Sprintf("%016d", imeisv)
		ue.MSIN = fmt.Sprintf("%010d", msin)
		s.ue = append(s.ue, &ue)

		imeisv += uint64(100) // serial number ++
		msin += uint64(1)
	}
	return
}
