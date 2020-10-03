package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type testSession struct {
	conn *sctp.SCTPConn
	info *sctp.SndRcvInfo
	gnb  *ngap.GNB
	ue   *nas.UE
}

func newTest() (t *testSession) {

	t = new(testSession)

	return
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

func initRANwithoutSCTP() (t *testSession) {

	t = new(testSession)
	gnb := ngap.NewNGAP("example.json")
	gnb.SetDebugLevel(1)

	t.gnb = gnb

	return
}

func (t *testSession) initUE() {
	t.ue = &t.gnb.UE
	t.ue.PowerON()
	t.ue.SetDebugLevel(1)
	return
}

func (t *testSession) registrateUE() {

	pdu := t.ue.MakeRegistrationRequest()
	t.gnb.RecvfromUE(&pdu)

	buf := t.gnb.MakeInitialUEMessage()
	t.sendtoAMF(buf)
	t.recvfromAMF()

	pdu = t.ue.MakeAuthenticationResponse()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
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

	return
}

func (t *testSession) establishPDUSession() {

	pdu := t.ue.MakePDUSessionEstablishmentRequest()
	t.gnb.RecvfromUE(&pdu)
	buf := t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF()

	buf = t.gnb.MakePDUSessionResourceSetupResponse()
	t.sendtoAMF(buf)

	return
}

func (t *testSession) setupN3Tunnel(ctx context.Context) {

	gnb := t.gnb
	ue := t.ue

	log.Printf("test: GTPuIFname: %s\n", gnb.GTPuIFname)
	log.Printf("test: GTP-U Peer: %v\n", gnb.Recv.GTPuPeerAddr)
	log.Printf("test: GTP-U Peer TEID: %v\n", gnb.Recv.GTPuPeerTEID)
	log.Printf("test: GTP-U Local TEID: %v\n", gnb.GTPuTEID)
	log.Printf("test: UE address: %v\n", ue.Recv.PDUAddress)

	addr, err := net.ResolveUDPAddr("udp", gnb.GTPuAddr+gtpv1.GTPUPort)
	if err != nil {
		log.Fatalf("failed to net.ResolveUDPAddr: %v", err)
		return
	}
	fmt.Printf("test: gNB UDP local address: %v\n", addr)
	uConn := gtpv1.NewUPlaneConn(addr)
	//defer uConn.Close()

	if err = uConn.EnableKernelGTP("gtp-gnb", gtpv1.RoleSGSN); err != nil {
		log.Fatalf("failed to EnableKernelGTP: %v", err)
		return
	}

	go func() {
		if err := uConn.ListenAndServe(ctx); err != nil {
			log.Println(err)
			return
		}
		log.Println("uConn.ListenAndServe exited")
	}()

	if err := uConn.AddTunnelOverride(
	    gnb.Recv.GTPuPeerAddr, ue.Recv.PDUAddress,
	    gnb.Recv.GTPuPeerTEID, gnb.GTPuTEID); err != nil {
			log.Println(err)
			return
	}

	if err = t.addRoute(uConn); err != nil {
		log.Fatalf("failed to addRoute: %v", err)
		return
	}

	err = t.addIP()
	if err != nil {
		log.Fatalf("failed to addIP: %v", err)
		return
	}

	err = t.addRuleLocal()
	if err != nil {
		log.Fatalf("failed to addRuleLocal: %v", err)
		return
	}

	go t.runUPlane(ctx)

	select {
	case <-ctx.Done():
			log.Fatalf("exit gnbsim")
	}

	return
}

func (t *testSession) addIP() (err error) {

	gnb := t.gnb
	ue := t.ue

	link, err := netlink.LinkByName(gnb.GTPuIFname)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	netToAdd := &net.IPNet{
		IP:   ue.Recv.PDUAddress,
		Mask: net.CIDRMask(28, 32),
	}

	var addr netlink.Addr
	var found bool
	for _, a := range addrs {
		if a.Label != gnb.GTPuIFname {
			continue
		}
		found = true
		//fmt.Printf("got=%v, toset=%v\n", a.IPNet.String(), netToAdd.String())
		if a.IPNet.String() == netToAdd.String() {
			return
		}
		addr = a
	}

	if !found {
		err = fmt.Errorf("cannot find the interface to add address: %s",
			gnb.GTPuIFname)
		return
	}

	addr.IPNet = netToAdd
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}
	return
}

const routeTableID = 1001

func (t *testSession) addRoute(uConn *gtpv1.UPlaneConn) (err error) {

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}, // default route
		LinkIndex: uConn.GTPLink.Attrs().Index, // dev gtp-<ECI>
		Scope:     netlink.SCOPE_LINK,          // scope link
		Protocol:  4,                           // proto static
		Priority:  1,                           // metric 1
		Table:     routeTableID,                // table <ECI>
	}

	err = netlink.RouteReplace(route)
	return
}

func (t *testSession) addRuleLocal() (err error) {

	ue := t.ue

	// 0: NETLINK_ROUTE, no definition found.
	rules, err := netlink.RuleList(0)
	if err != nil {
		return err
	}

	mask32 := &net.IPNet{IP: ue.Recv.PDUAddress, Mask: net.CIDRMask(32, 32)}
	for _, r := range rules {
		if r.Src == mask32 && r.Table == routeTableID {
			return
		}
	}

	rule := netlink.NewRule()
	rule.Src = mask32
	rule.Table = routeTableID
	err = netlink.RuleAdd(rule)

	return
}

func (t *testSession) runUPlane(ctx context.Context) {

	fmt.Printf("runUPlane\n")

	ue := t.ue

	laddr, err := net.ResolveTCPAddr("tcp", ue.Recv.PDUAddress.String()+":0")
	if err != nil {
		return
	}

	dialer := net.Dialer{LocalAddr: laddr}
	client := http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   3 * time.Second,
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			// do nothing here and go forward
		}

		rsp, err := client.Get(ue.URL)
		if err != nil {
			log.Fatalf("failed to GET %s: %s", ue.URL, err)
			continue
		}

		if rsp.StatusCode == http.StatusOK {
			log.Printf("[HTTP Probe] Successfully GET %s: "+
			"Status: %s", ue.URL, rsp.Status)
			rsp.Body.Close()
			continue
		}
		rsp.Body.Close()
		log.Printf("[HTTP Probe] got invalid response on HTTP probe: %v",
		    rsp.StatusCode)
	}
	return
}

func runN3test() (err error) {

	t := initRANwithoutSCTP()
	t.initUE()

	gnb := t.gnb
	ue := t.ue

	// temporary setting
	gnb.Recv.GTPuPeerAddr = net.ParseIP("192.168.1.18")
	gnb.Recv.GTPuPeerTEID = 0x12345678
	ue.Recv.PDUAddress = net.ParseIP("60.60.60.1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.setupN3Tunnel(ctx)

	return
}

func main() {

	log.SetPrefix("[gnbsim]")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	n3test := false

	if n3test {
		runN3test()
		return
	}

	// usual testing
	t := initRAN()
	t.initUE()

	t.registrateUE()
	time.Sleep(time.Second * 3)

	t.establishPDUSession()
	time.Sleep(time.Second * 3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.setupN3Tunnel(ctx)
	time.Sleep(time.Second * 3)

	return
}
