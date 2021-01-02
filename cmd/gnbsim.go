package main

import (
	"fmt"
	"github.com/ishidawataru/sctp"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/gtp"
)

type GnbsimSession struct {
	n1conn *sctp.SCTPConn
	n1info *sctp.SndRcvInfo
	gnb    *ngap.GNB
	ue     *[]nas.UE
	gtpu   *gtp.GTP
}

func main() {
	fmt.Printf("gnbsim\n")
}
