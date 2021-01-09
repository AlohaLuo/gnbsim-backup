// Copyright 2019-2021 hhorai. All rights reserved.
// Use of this source code is governed by a MIT license that can be found
// in the LICENSE file.
package main

import (
	"fmt"
)

func (s *GnbsimSession) initUEs() (err error) {

	for _, ue := range s.ue {
		ue.PowerON()
	}
	fmt.Printf("InitUEs")
	return
}
