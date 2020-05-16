package main

import (
	"flag"
	"fmt"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"log"
	"net"
	"strings"
)

func main() {
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
	log.Printf("Dail LocalAddr: %s; RemoteAddr: %s", conn.LocalAddr(), conn.RemoteAddr())

	sndbuf, err := conn.GetWriteBuffer()
	rcvbuf, err := conn.GetReadBuffer()
	log.Printf("SndBufSize: %d, RcvBufSize: %d", sndbuf, rcvbuf)

	ppid := 0
	info := &sctp.SndRcvInfo{
		Stream: uint16(ppid),
		PPID:   0x3c000000,
	}

	conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)

	gnb := ngap.NewNGAP("example.json")
	buf := []byte{}

	sendbuf := gnb.MakeNGSetupRequest()
	n, err := conn.SCTPWrite(sendbuf, info)

	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}

	log.Printf("write: len %d", n)

	buf = make([]byte, 1500)
	n, info, err = conn.SCTPRead(buf)

	if err != nil {
		log.Fatalf("failed to read: %v", err)
	}

	log.Printf("read: len %d, info: %+v", n, info)
	buf = buf[:n]
	fmt.Printf("dump: %x\n", buf)
	gnb.Decode(&buf)

	sendbuf = gnb.MakeInitialUEMessage()
	n, err = conn.SCTPWrite(sendbuf, info)

	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}

	log.Printf("write: len %d", n)

	buf = make([]byte, 1500)
	n, info, err = conn.SCTPRead(buf)

	if err != nil {
		log.Fatalf("failed to read: %v", err)
	}

	log.Printf("read: len %d, info: %+v", n, info)
	buf = buf[:n]
	fmt.Printf("dump: %x\n", buf)
	gnb.Decode(&buf)

	sendbuf = gnb.MakeUplinkNASTransport()
	n, err = conn.SCTPWrite(sendbuf, info)

	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}

	log.Printf("write: len %d", n)

	buf = make([]byte, 1500)
	n, info, err = conn.SCTPRead(buf)

	if err != nil {
		log.Fatalf("failed to read: %v", err)
	}

	log.Printf("read: len %d, info: %+v", n, info)
	buf = buf[:n]
	fmt.Printf("dump: %x\n", buf)
	gnb.Decode(&buf)

	return
}
