package main

import (
	"flag"
	"fmt"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"log"
	"net"
	"strings"
	"time"
)

type testSession struct {
	conn *sctp.SCTPConn
	info *sctp.SndRcvInfo
	gnb  *ngap.GNB
	ue   *nas.UE
}

func setupSCTP() (conn *sctp.SCTPConn, info *sctp.SndRcvInfo) {

	var ip = flag.String("ip", "localhost", "destinaion ip address")
	var port = flag.Int("port", 38412, "destination port")
	var lport = flag.Int("lport", 38412, "local port")

	flag.Parse()

	ips := []net.IPAddr{}

	for _, i := range strings.Split(*ip, ",") {
		a, _ := net.ResolveIPAddr("ip", i)
		ips = append(ips, *a)
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}

	var laddr *sctp.SCTPAddr
	if *lport != 0 {
		laddr = &sctp.SCTPAddr{
			Port: *lport,
		}
	}

	conn, err := sctp.DialSCTP("sctp", laddr, addr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	log.Printf("Dail LocalAddr: %s; RemoteAddr: %s",
		conn.LocalAddr(), conn.RemoteAddr())

	sndbuf, err := conn.GetWriteBuffer()
	rcvbuf, err := conn.GetReadBuffer()
	log.Printf("SndBufSize: %d, RcvBufSize: %d", sndbuf, rcvbuf)

	ppid := 0
	info = &sctp.SndRcvInfo{
		Stream: uint16(ppid),
		PPID:   0x3c000000,
	}

	conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)

	return
}

func (t *testSession) sendtoAMF(pdu []byte) {

	n, err := t.conn.SCTPWrite(pdu, t.info)
	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}
	log.Printf("write: len %d, info: %+v", n, t.info)
	return
}

func (t *testSession) recvfromAMF() {

	buf := make([]byte, 1500)
	n, info, err := t.conn.SCTPRead(buf)
	t.info = info

	if err != nil {
		log.Fatalf("failed to read: %v", err)
	}
	log.Printf("read: len %d, info: %+v", n, t.info)

	buf = buf[:n]
	fmt.Printf("dump: %x\n", buf)
	t.gnb.Decode(&buf)

	return
}

func initRAN() (t *testSession) {

	t = new(testSession)
	gnb := ngap.NewNGAP("example.json")
	gnb.SetDebugLevel(1)

	conn, info := setupSCTP()

	t.gnb = gnb
	t.conn = conn
	t.info = info

	pdu := gnb.MakeNGSetupRequest()
	t.sendtoAMF(pdu)
	t.recvfromAMF()

	return
}

func (t *testSession) initUE() {
	t.ue = &t.gnb.UE
	t.ue.PowerON()
	t.ue.SetDebugLevel(1)
	return
}

func (t *testSession) registrationRequest() {

	pdu := t.ue.MakeRegistrationRequest()
	t.gnb.RecvfromUE(&pdu)
	sendbuf := t.gnb.MakeInitialUEMessage()

	n, err := t.conn.SCTPWrite(sendbuf, t.info)

	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}
	log.Printf("write: len %d", n)

	return
}

func main() {

	t := initRAN()
	t.initUE()

	t.registrationRequest()
	t.recvfromAMF()

	pdu := t.ue.MakeAuthenticationResponse()
	t.gnb.RecvfromUE(&pdu)
	buf := t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF()

	pdu = t.ue.MakeSecurityModeComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF()

	buf = t.gnb.MakeInitialContextSetupResponse()
	t.sendtoAMF(buf)

	pdu = t.ue.MakeRegistrationComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)

	time.Sleep(time.Second * 1)

	pdu = t.ue.MakePDUSessionEstablishmentRequest()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF()

	buf = t.gnb.MakePDUSessionResourceSetupResponse()
	t.sendtoAMF(buf)
	time.Sleep(time.Second * 5)

	return
}
