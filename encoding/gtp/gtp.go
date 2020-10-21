// Copyright 2020 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.

// Package gtp is implementation for GTPv1-U in the 5GS Sytem.
// document version: 3GPP TS 29.281 v16.1.0 (2020-09)

package gtp

import (
	"net"
)

const (
	Port = 2152
)

type GTP struct {
	IFname    string
	LocalAddr net.IP
	LocalTEID uint32
	PeerAddr  net.IP
	PeerTEID  uint32
}

func NewGTP() (p *GTP) {

	var gtp GTP
	p = &gtp

	return
}

func (gtp *GTP) Encap(pdu *[]byte) {
	return
}

func (gtp *GTP) Decap(pdu *[]byte) {
	return
}
