// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm2

import (
	"math/big"
)

type Sm2PrivateKey struct {
	D *big.Int //sk
}

type Sm2PublicKey struct {
	X *big.Int //pk.X
	Y *big.Int //pk.Y
}
