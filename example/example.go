package main

import (
	"context"
	"fmt"
	"github.com/hhorai/gnbsim/encoding/gtp"
	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"net/http"
	"time"
)

type testSession struct {
	conn *sctp.SCTPConn
	info *sctp.SndRcvInfo
	gnb  *ngap.GNB
	//gtpu *gtp.GTP
}

func newTest() (t *testSession) {

	t = new(testSession)

	return
}

func setupSCTP(gnb *ngap.GNB) (conn *sctp.SCTPConn, info *sctp.SndRcvInfo) {

	const amfPort = 38412
	amfAddr, _ := net.ResolveIPAddr("ip", gnb.NGAPPeerAddr)

	ips := []net.IPAddr{*amfAddr}
	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    amfPort,
	}

	conn, err := sctp.DialSCTP("sctp", nil, addr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	log.Printf("Dail LocalAddr: %s; RemoteAddr: %s",
		conn.LocalAddr(), conn.RemoteAddr())

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

	conn, info := setupSCTP(gnb)

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

	gnb := t.gnb
	tmp := t.gnb.UE
	ue := &tmp
	ue.PowerON()
	ue.SetDebugLevel(1)
	gnb.CampIn(ue)

	return
}

func (t *testSession) registrteAll() {
	gnb := t.gnb
	for _, c := range gnb.Camper {
		ue := c.UE
		t.registrateUE(ue)
	}
}

func (t *testSession) registrateUE(ue *nas.UE) {

	gnb := t.gnb

	pdu := ue.MakeRegistrationRequest()
	gnb.RecvfromUE(ue, &pdu)

	buf := gnb.MakeInitialUEMessage(ue)
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	pdu = ue.MakeAuthenticationResponse()
	gnb.RecvfromUE(ue, &pdu)
	buf = gnb.MakeUplinkNASTransport(ue)
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	pdu = ue.MakeSecurityModeComplete()
	gnb.RecvfromUE(ue, &pdu)
	buf = gnb.MakeUplinkNASTransport(ue)
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = gnb.MakeInitialContextSetupResponse(ue)
	t.sendtoAMF(buf)

	pdu = ue.MakeRegistrationComplete()
	gnb.RecvfromUE(ue, &pdu)
	buf = gnb.MakeUplinkNASTransport(ue)
	t.sendtoAMF(buf)

	// for Configuration Update Command from open5gs AMF.
	t.recvfromAMF(3)

	return
}

func (t *testSession) deregistrateAll() {
	gnb := t.gnb
	for _, c := range gnb.Camper {
		ue := c.UE
		t.deregistrateUE(ue)
	}
}

func (t *testSession) deregistrateUE(ue *nas.UE) {

	gnb := t.gnb

	pdu := ue.MakeDeregistrationRequest()
	gnb.RecvfromUE(ue, &pdu)
	buf := gnb.MakeUplinkNASTransport(ue)
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	return
}

func (t *testSession) establishPDUSessionAll() {
	gnb := t.gnb
	for _, c := range gnb.Camper {
		ue := c.UE
		t.establishPDUSession(ue)
	}
}

func (t *testSession) establishPDUSession(ue *nas.UE) {

	gnb := t.gnb

	pdu := ue.MakePDUSessionEstablishmentRequest()
	gnb.RecvfromUE(ue, &pdu)
	buf := gnb.MakeUplinkNASTransport(ue)
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = gnb.MakePDUSessionResourceSetupResponse(ue)
	t.sendtoAMF(buf)

	return
}

func (t *testSession) setupN3Tunnel() (gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	gnb := t.gnb
	log.Printf("GTP-U interface name: %s\n", gnb.GTPuIFname)
	log.Printf("GTP-U local addr: %v\n", gnb.GTPuLocalAddr)
	log.Printf("GTP-U peer addr : %v\n", gnb.Recv.GTPuPeerAddr)

	laddr := &net.UDPAddr{
		IP:   net.ParseIP(gnb.GTPuLocalAddr),
		Port: gtp.Port,
	}

	gtpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalln(err)
		return
	}

	tun, err = addTunnel("gtp-gnb")
	if err != nil {
		log.Fatalln(err)
		return
	}

	if err = addRoute(tun); err != nil {
		log.Fatalf("failed to addRoute: %v", err)
		return
	}

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

const routeTableID = 1001

func addRoute(tun *netlink.Tuntap) (err error) {

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}, // default route
		LinkIndex: tun.Attrs().Index,  // dev gtp-<ECI>
		Scope:     netlink.SCOPE_LINK, // scope link
		Protocol:  4,                  // proto static
		Priority:  1,                  // metric 1
		Table:     routeTableID,       // table <ECI>
	}

	err = netlink.RouteReplace(route)
	return
}

func (t *testSession) runUPlaneAll(
	ctx context.Context, gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	for _, c := range t.gnb.Camper {
		t.runUPlane(ctx, c, gtpConn, tun)
	}
	return
}

func (t *testSession) runUPlane(ctx context.Context, c *ngap.Camper,
	gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	gnb := t.gnb
	ue := c.UE
	c.GTPu = gtp.NewGTP(gnb.GTPuTEID, gnb.Recv.GTPuPeerTEID)
	gtpu := c.GTPu
	gtpu.SetExtensionHeader(true)
	gtpu.SetQosFlowID(c.QosFlowID)

	log.Printf("GTP-U Peer TEID: %v\n", gnb.Recv.GTPuPeerTEID)
	log.Printf("GTP-U Local TEID: %v\n", gnb.GTPuTEID)
	log.Printf("QoS Flow ID: %d\n", gtpu.QosFlowID)

	log.Printf("UE address: %v\n", ue.Recv.PDUAddress)
	err := addIP(gnb.GTPuIFname, ue.Recv.PDUAddress, 28)
	if err != nil {
		log.Fatalf("failed to addIP: %v", err)
		return
	}

	err = addRuleLocal(ue.Recv.PDUAddress)
	if err != nil {
		log.Fatalf("failed to addRuleLocal: %v", err)
		return
	}

	go t.decap(c, gtpConn, tun)
	go t.encap(c, gtpConn, tun)
	t.doUPlane(ctx, c)

	/*
		select {
		case <-ctx.Done():
			log.Fatalf("exit gnbsim")
		}
	*/
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

	netToAdd := &net.IPNet{
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

func addRuleLocal(ip net.IP) (err error) {

	// 0: NETLINK_ROUTE, no definition found.
	rules, err := netlink.RuleList(0)
	if err != nil {
		return err
	}

	mask32 := &net.IPNet{
		IP:   ip,
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

func (t *testSession) decap(c *ngap.Camper, gtpConn *net.UDPConn, tun *netlink.Tuntap) {

	fd := tun.Fds[0]

	buf := make([]byte, 2048)
	for {
		n, _, err := gtpConn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln(err)
			return
		}
		payload := c.GTPu.Decap(buf[:n])
		//fmt.Printf("decap: %x\n", payload)

		_, err = fd.Write(payload)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}
}

func (t *testSession) encap(c *ngap.Camper, gtpConn *net.UDPConn, tun *netlink.Tuntap) {

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
		payload := c.GTPu.Encap(buf[:n])

		_, err = gtpConn.WriteToUDP(payload, paddr)
		if err != nil {
			log.Fatalln(err)
			return
		}
	}
	return
}

func (t *testSession) doUPlane(ctx context.Context, c *ngap.Camper) {

	fmt.Printf("doUPlane\n")

	ue := c.UE

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
			return
		}
		rsp.Body.Close()
		log.Printf("[HTTP Probe] got invalid response on HTTP probe: %v",
			rsp.StatusCode)
	}
	return
}

func main() {

	log.SetPrefix("[gnbsim]")
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)

	// usual testing
	t := initRAN()
	t.initUE()

	t.registrteAll()
	time.Sleep(time.Second * 1)

	t.establishPDUSessionAll()
	time.Sleep(time.Second * 1)

	gtpConn, tun := t.setupN3Tunnel()
	time.Sleep(time.Second * 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.runUPlaneAll(ctx, gtpConn, tun)
	time.Sleep(time.Second * 1)

	t.deregistrateAll()
	time.Sleep(time.Second * 1)

	return
}
