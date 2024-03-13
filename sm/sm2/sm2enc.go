// Copyright 2020 cetc-30. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sm2

import (
	"fmt"
	"github.com/xlcetc/cryptogm/elliptic/sm2curve"
	"io"
	"math/big"
)

var T2x = make([]*big.Int, 256)
var T2y = make([]*big.Int, 256)
var T1 = make(map[string]int64, 16777216)

func LgwHEnc(rand io.Reader, key *PublicKey, m *big.Int) (x1, y1, c2x, c2y *big.Int) {
	k := generateRandK(rand, key.Curve)
	// C1 = k[G]
	x1, y1 = key.Curve.ScalarBaseMult(k.Bytes())
	var x2, y2 *big.Int
	// [k]PK
	x2, y2 = key.Curve.ScalarMult(key.X, key.Y, k.Bytes())
	mGx, mGy := key.Curve.ScalarBaseMult(m.Bytes())
	c2x = new(big.Int)
	c2y = new(big.Int)
	c2x, c2y = key.Curve.Add(mGx, mGy, x2, y2)
	return x1, y1, c2x, c2y
}

func LgwHDec(key *PrivateKey, c1x, c1y, c2x, c2y *big.Int) (int, error) {
	fmt.Printf("\n\nkey: %v\nc1x: %v\nc1y: %v\nc2x: %v\nc2y: %v\n", key, c1x, c1y, c2x, c2y)
	var m int = -1
	x2, y2 := key.Curve.ScalarMult(c1x, c1y, key.D.Bytes())
	inv_y2 := new(big.Int)
	inv_y2.Add(key.Curve.Params().P, inv_y2)
	inv_y2.Sub(inv_y2, y2)
	mGx, mGy := key.Curve.Add(c2x, c2y, x2, inv_y2)
	j := 0
	for ; j < 256; j++ {
		if j == 0 {
			i, ok := T1[mGx.String()]
			if ok {
				m = int(i)
				break
			}
		}
		x3, _ := key.Curve.Add(mGx, mGy, T2x[j], T2y[j])
		if i, ok := T1[x3.String()]; ok {
			m = j*16777216 + int(i)
			break
		}
	}
	return m, nil
}

func init() {
	c := sm2curve.P256()
	var i int64 = 2
	//var k int64 = 1
	//16777216,4096
	x := big.NewInt(0)
	x.Add(c.Params().Gx, x)
	y := big.NewInt(0)
	y.Add(c.Params().Gy, y)

	T1[c.Params().Gx.String()] = 1

	total := 16777216 // 总迭代次数
	percentStep := 1  // 每1%进度更新一次
	lastPercent := -1 // 初始化为-1，确保第一次进度会被打印

	for ; i <= 16777216; i++ {
		//fmt.Printf("%d\n", i)
		x, y = c.Add(x, y, c.Params().Gx, c.Params().Gy)
		T1[x.String()] = i
		if i == 44 {
			fmt.Println(x.String())
		}

		// 计算当前进度的百分比
		currentPercent := int(float64(i) / float64(total) * 100)
		if currentPercent != lastPercent && currentPercent%percentStep == 0 {
			fmt.Printf("当前进度：%d%%\n", currentPercent)
			lastPercent = currentPercent
		}
	}
	var j int64 = 0
	//t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(4096).Bytes())
	t1lastx, t1lasty := c.ScalarMult(c.Params().Gx, c.Params().Gy, big.NewInt(16777216).Bytes())
	for ; j < 256; j++ {
		//fmt.Printf("%d\n", j)
		jbigint := big.NewInt(j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.Params().P, inv_t2y)
		//fmt.Println(c.Params().P)
		inv_t2y.Sub(inv_t2y, t2y)
		T2x[j] = t2x
		T2y[j] = inv_t2y
		//fmt.Println(T2x[j])
		//fmt.Println(T2y[j])
	}
}
