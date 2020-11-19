package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hhorai/gnbsim/encoding/gtp"
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
	gtpu *gtp.GTP
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

func (t *testSession) recvfromAMF(timeout time.Duration) {

	const defaultTimer = 10 // sec

	if timeout == 0 {
		timeout = defaultTimer
	}

	c := make(chan bool, 1)
	go func() {
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
		c <- true
	}()
	select {
	case <-c:
		break
	case <-time.After(timeout * time.Second):
		log.Printf("read: timeout")
	}
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
	t.recvfromAMF(0)

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
	t.recvfromAMF(0)

	pdu = t.ue.MakeAuthenticationResponse()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	pdu = t.ue.MakeSecurityModeComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = t.gnb.MakeInitialContextSetupResponse()
	t.sendtoAMF(buf)

	pdu = t.ue.MakeRegistrationComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)

	// for Configuration Update Command from open5gs AMF.
	t.recvfromAMF(3)

	return
}

func (t *testSession) establishPDUSession() {

	pdu := t.ue.MakePDUSessionEstablishmentRequest()
	t.gnb.RecvfromUE(&pdu)
	buf := t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = t.gnb.MakePDUSessionResourceSetupResponse()
	t.sendtoAMF(buf)

	return
}

func (t *testSession) setupN3Tunnel2(ctx context.Context) {

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

	if err = addRoute2(uConn); err != nil {
		log.Fatalf("failed to addRoute2: %v", err)
		return
	}

	err = addIP(gnb.GTPuIFname, ue.Recv.PDUAddress, 28)
	if err != nil {
		log.Fatalf("failed to addIP: %v", err)
		return
	}

	err = addRuleLocal(ue.Recv.PDUAddress)
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

func (t *testSession) setupN3Tunnel(ctx context.Context) {

	gnb := t.gnb
	ue := t.ue

	log.Printf("test: GTPuIFname: %s\n", gnb.GTPuIFname)
	log.Printf("test: GTP-U Peer: %v\n", gnb.Recv.GTPuPeerAddr)
	log.Printf("test: GTP-U Peer TEID: %v\n", gnb.Recv.GTPuPeerTEID)
	log.Printf("test: GTP-U Local TEID: %v\n", gnb.GTPuTEID)
	log.Printf("test: UE address: %v\n", ue.Recv.PDUAddress)
	laddr := &net.UDPAddr{
		IP:   net.ParseIP(gnb.GTPuAddr),
		Port: gtp.Port,
	}
	fmt.Printf("test: gNB UDP local address: %v\n", laddr)

	gtpu := gtp.NewGTP(gnb.GTPuTEID, gnb.Recv.GTPuPeerTEID)
	t.gtpu = gtpu

	gtpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalln(err)
		return
	}

	tun, err := addTunnel("gtp-gnbsim")
	if err != nil {
		log.Fatalln(err)
		return
	}

	go t.decap(gtpConn, tun)

	if err = addRoute(tun); err != nil {
		log.Fatalf("failed to addRoute: %v", err)
		return
	}

	err = addIP(gnb.GTPuIFname, ue.Recv.PDUAddress, 28)
	if err != nil {
		log.Fatalf("failed to addIP: %v", err)
		return
	}

	err = addRuleLocal(ue.Recv.PDUAddress)
	if err != nil {
		log.Fatalf("failed to addRuleLocal: %v", err)
		return
	}

	t.encap(gtpConn, tun)

	return
}

func addTunnel(tunname string) (tun *netlink.Tuntap, err error) {

	tun = &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tunname},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		Queues:    1,
	}
	if err = netlink.LinkAdd(tun); err != nil {
		err = fmt.Errorf("failed to ADD tun device=gtp0: %s", err)
		return
	}
	if err = netlink.LinkSetUp(tun); err != nil {
		err = fmt.Errorf("failed to UP tun device=gtp0: %s", err)
		return
	}
	return
}

func addIP(ifname string, ip net.IP, masklen int) (err error) {

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	netToAdd := &net.IPNet {
		IP:   ip,
		Mask: net.CIDRMask(masklen, 32),
	}

	var addr netlink.Addr
	var found bool
	for _, a := range addrs {
		if a.Label != ifname {
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
		err = fmt.Errorf(
		    "cannot find the interface to add address: %s", ifname)
		return
	}

	addr.IPNet = netToAdd
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}
	return
}

const routeTableID = 1001

func addRoute(tun *netlink.Tuntap) (err error) {

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}, // default route
		LinkIndex: tun.Attrs().Index,   // dev gtp-<ECI>
		Scope:     netlink.SCOPE_LINK,  // scope link
		Protocol:  4,                   // proto static
		Priority:  1,                   // metric 1
		Table:     routeTableID,        // table <ECI>
	}

	err = netlink.RouteReplace(route)
	return
}

//uConn *netlink.Tuntap) (err error) {
func addRoute2(uConn *gtpv1.UPlaneConn) (err error) {

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}, // default route
		LinkIndex:  uConn.KernelGTP.Link.Attrs().Index,   // dev gtp-<ECI>
		Scope:     netlink.SCOPE_LINK,  // scope link
		Protocol:  4,                   // proto static
		Priority:  1,                   // metric 1
		Table:     routeTableID,        // table <ECI>
	}

	err = netlink.RouteReplace(route)
	return
}

func addRuleLocal(ip net.IP) (err error) {

	// 0: NETLINK_ROUTE, no definition found.
	rules, err := netlink.RuleList(0)
	if err != nil {
		return err
	}

	mask32 := &net.IPNet {
		IP: ip,
		Mask: net.CIDRMask(32, 32),
	}

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

func (t *testSession) decap(gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	fd := tun.Fds[0]

	buf := make([]byte, 2048)
	for {
		n, addr, err := gtpConn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln(err)
			return
		}
		fmt.Printf("n=%d, addr=%v\n", n, addr)

		payload := t.gtpu.Decap(buf[:n])

		n, err = fd.Write(payload)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}
}


func (t *testSession) encap(gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	fd := tun.Fds[0]
	paddr := &net.UDPAddr{
		IP:   t.gnb.Recv.GTPuPeerAddr,
		Port: gtp.Port,
	}

	buf := make([]byte, 2048)
	for {
		n, err := fd.Read(buf)
		if err != nil {
			log.Fatalln(err)
			return
		}
		fmt.Printf("n=%d\n", n)

		buf = t.gtpu.Encap(buf[:n])

		n, err = gtpConn.WriteToUDP(buf, paddr)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}
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
	t.setupN3Tunnel2(ctx)
	time.Sleep(time.Second * 3)

	return
}
