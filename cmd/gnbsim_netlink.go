// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.
package main

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
)

func addTunnel(name string) (tun *netlink.Tuntap, err error) {

	tun = &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: name},
		Mode:      netlink.TUNTAP_MODE_TUN,
		Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
		Queues:    1,
	}

	if err = netlink.LinkAdd(tun); err != nil {
		err = fmt.Errorf("failed to add tun device[%s]: %s", name, err)
		return
	}

	if err = netlink.LinkSetUp(tun); err != nil {
		err = fmt.Errorf("failed to up tun device[%s]: %s", name, err)
		return
	}
	return
}

func addIPv4Address(ifName string, ip net.IP, masklen int) (err error) {

	link, err := netlink.LinkByName(ifName)
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
	found := false
	for _, a := range addrs {
		if a.Label != ifName {
			continue
		}
		found = true
		if a.IPNet.String() == netToAdd.String() {
			// The IP address has already been set.
			return
		}
		addr = a
	}

	if !found {
		err = fmt.Errorf("interface[%s] not found", ifName)
		return
	}

	addr.IPNet = netToAdd
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}
	return
}
