// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"crypto"
	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	"io"
	"math/big"
)

type PublicKey struct {
	sm2curve.Curve
	X, Y        *big.Int
	PreComputed *[37][64 * 8]uint64 //precomputation
}

type PrivateKey struct {
	PublicKey
	D    *big.Int
	DInv *big.Int //(1+d)^-1
}

var generateRandK = _generateRandK

// optMethod includes some optimized methods.
type optMethod interface {
	// CombinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
	CombinedMult(Precomputed *[37][64 * 8]uint64, baseScalar, scalar []byte) (x, y *big.Int)
	// InitPubKeyTable implements precomputed table of public key
	InitPubKeyTable(x, y *big.Int) (Precomputed *[37][64 * 8]uint64)
	// PreScalarMult implements fast multiplication of public key
	PreScalarMult(Precomputed *[37][64 * 8]uint64, scalar []byte) (x, y *big.Int)
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

var one = new(big.Int).SetInt64(1)

func GenerateKey(rand io.Reader) (*PrivateKey, error) {
	c := sm2curve.P256()

	k := _generateRandK(rand, c)
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	//(1+d)^-1
	priv.DInv = new(big.Int).Add(k, one)
	priv.DInv.ModInverse(priv.DInv, c.Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	if opt, ok := c.(optMethod); ok {
		priv.PreComputed = opt.InitPubKeyTable(priv.PublicKey.X, priv.PublicKey.Y)
	}
	return priv, nil
}

func _generateRandK(rand io.Reader, c sm2curve.Curve) (k *big.Int) {
	params := c.Params()
	two := big.NewInt(2)
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	return
}
