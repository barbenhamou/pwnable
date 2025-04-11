package lls

import (
	"fmt"
	"math/big"
)

// Point represents a point on the SM2 curve
type Point struct {
	x, y *GaloisFieldElement
	sm2  *SM2
}

// IsOnCurve checks if a point is on the curve
func (pt *Point) IsOnCurve() bool {
	// y^2 = x^3 + ax + b
	// Compute left and right sides
	lhs := pt.y.Square()
	rhs := pt.x.Square().Mul(pt.x).Add(pt.sm2.a().Mul(pt.x)).Add(pt.sm2.b())
	return lhs.Cmp(rhs) == 0
}

// IsZero checks if a point is the identity point
func (pt *Point) IsZero() bool {
	zeroPoint := pt.sm2.ZeroPoint()
	return pt.Equals(zeroPoint)
}

// Neg computes -P for a point P
func (pt *Point) Neg() *Point {
	return &Point{
		x:   pt.x,
		y:   pt.y.Neg(),
		sm2: pt.sm2,
	}

}

// Copy creates a copy of the point
func (pt *Point) Copy() *Point {
	x, y := &pt.x.Int, &pt.y.Int
	return &Point{
		x:   pt.sm2.field.NewElement(*x),
		y:   pt.sm2.field.NewElement(*y),
		sm2: pt.sm2,
	}
}

// Add performs point addition for the SM2 curve using the correct formulas.
func (pt *Point) Add(q *Point) *Point {
	if pt.IsZero() {
		return q.Copy()
	}

	if q.IsZero() {
		return pt.Copy()
	}

	if pt.Neg().Equals(q) {
		return pt.sm2.ZeroPoint()
	}

	if pt.Equals(q) {
		return pt.Double()
	}

	// Now according to the formula
	// P + Q = R
	// l = (yq - yp) / (xq - xp)
	// xr = l^2 - xp - xq
	// yr = l(xp - xr) - yp

	yq_yp := q.y.Sub(pt.y)
	xq_xp := q.x.Sub(pt.x)
	inverse_xq_xp, err := xq_xp.ModInverse()
	if err != nil {
		panic("invalid point for addition")
	}
	l := yq_yp.Mul(inverse_xq_xp)
	xr := l.Square().Sub(pt.x).Sub(q.x)
	yr := l.Mul(pt.x.Sub(xr)).Sub(pt.y)

	return &Point{
		x:   xr,
		y:   yr,
		sm2: pt.sm2,
	}
}

func (pt *Point) Double() *Point {
	// Now according to the formula
	// P + P = 2P = R
	// l = (3 * xp^2 + a) / (2 * yp)
	// xr = l^2 - 2xp
	// yr = l(xp - xr) - yp
	three := pt.sm2.field.NewElement(*big.NewInt(3))
	two := pt.sm2.field.NewElement(*big.NewInt(2))
	xp2 := pt.x.Square()
	_2yp := pt.y.Mul(two)
	inverse_2yp, err := _2yp.ModInverse()
	if err != nil {
		panic("invalid point for doubling")
	}
	nominator := xp2.Mul(three).Add(pt.sm2.a())
	l := nominator.Mul(inverse_2yp)
	xr := l.Square().Sub(pt.x.Mul(two))
	yr := l.Mul(pt.x.Sub(xr)).Sub(pt.y)

	return &Point{
		x:   xr,
		y:   yr,
		sm2: pt.sm2,
	}
}

// ScalarMul computes kP for a scalar k
func (pt *Point) ScalarMul(k *big.Int) *Point {
	res := pt.sm2.ZeroPoint()
	temp := pt.Copy()

	for i := k.BitLen() - 1; i >= 0; i-- {
		res = res.Add(res)
		if k.Bit(i) == 1 {
			res = res.Add(temp)
		}
	}

	return res
}

func (pt *Point) Equals(rhs *Point) bool {
	return pt.x.Cmp(rhs.x) == 0 && pt.y.Cmp(rhs.y) == 0
}

func (pt *Point) Bytes() []byte {
	// Pad to 64 bytes
	var xBytes, yBytes [32]byte
	len_x := len(pt.x.Bytes())
	len_y := len(pt.y.Bytes())
	if len_x > 32 || len_y > 32 {
		panic("point coordinate overflow")
	}
	copy(xBytes[32-len(pt.x.Bytes()):], pt.x.Bytes())
	copy(yBytes[32-len(pt.y.Bytes()):], pt.y.Bytes())
	return append(xBytes[:], yBytes[:]...)

}

// String representation of the point
func (pt *Point) String() string {
	return fmt.Sprintf("X: %v, Y: %v", pt.x, pt.y)
}
