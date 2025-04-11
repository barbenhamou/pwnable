package lls

import (
	"fmt"
	"math/big"
)

// GaloisFieldElement represents an element in GF(p)
type GaloisField struct {
	p big.Int
}

func NewGaloisField(p big.Int) *GaloisField {
	return &GaloisField{p: p}
}

func (gf *GaloisField) NewElement(value big.Int) *GaloisFieldElement {
	v := new(big.Int).Mod(&value, &gf.p)
	return &GaloisFieldElement{Int: *v, field: gf}
}

type GaloisFieldElement struct {
	big.Int
	field *GaloisField
}

func (gfe *GaloisFieldElement) Set(value *GaloisFieldElement) {
	gfe.Int.Set(&value.Int)
}

func (gfe *GaloisFieldElement) Add(rhs *GaloisFieldElement) *GaloisFieldElement {
	res := new(big.Int).Add(&gfe.Int, &rhs.Int)
	res.Mod(res, &gfe.field.p)
	return &GaloisFieldElement{Int: *res, field: gfe.field}
}

func (gfe *GaloisFieldElement) Sub(rhs *GaloisFieldElement) *GaloisFieldElement {
	res := new(big.Int).Sub(&gfe.Int, &rhs.Int)
	res.Mod(res, &gfe.field.p)
	return &GaloisFieldElement{Int: *res, field: gfe.field}
}

func (gfe *GaloisFieldElement) Mul(rhs *GaloisFieldElement) *GaloisFieldElement {
	res := new(big.Int).Mul(&gfe.Int, &rhs.Int)
	res.Mod(res, &gfe.field.p)
	return &GaloisFieldElement{Int: *res, field: gfe.field}
}

func (gfe *GaloisFieldElement) Square() *GaloisFieldElement {
	return gfe.Mul(gfe)
}

func (gfe *GaloisFieldElement) Neg() *GaloisFieldElement {
	res := new(big.Int).Neg(&gfe.Int)
	res.Mod(res, &gfe.field.p)
	return &GaloisFieldElement{Int: *res, field: gfe.field}
}

func (gfe *GaloisFieldElement) ModInverse() (*GaloisFieldElement, error) {
	res := new(big.Int).ModInverse(&gfe.Int, &gfe.field.p)
	if res == nil {
		return nil, fmt.Errorf("Modular inverse does not exist")
	}
	return &GaloisFieldElement{Int: *res, field: gfe.field}, nil
}

func (gfe *GaloisFieldElement) Cmp(rhs *GaloisFieldElement) int {
	if gfe.field.p.Cmp(&rhs.field.p) != 0 {
		panic("Cannot compare elements from different fields")
	}
	return gfe.Int.Cmp(&rhs.Int)
}

func (gfe *GaloisFieldElement) Copy() *GaloisFieldElement {
	return gfe.field.NewElement(gfe.Int)
}

func (gfe *GaloisFieldElement) Bytes() []byte {
	// Big Endian
	bitLen := gfe.field.p.BitLen()
	rem := bool(bitLen%8 != 0)
	byteLen := bitLen / 8
	if rem {
		byteLen++
	}
	out := make([]byte, byteLen)
	copy(out[len(out)-len(gfe.Int.Bytes()):], gfe.Int.Bytes())
	return out
}
func (gfe *GaloisFieldElement) String() string {
	return fmt.Sprintf("%v (mod %v)", gfe.Int.String(), gfe.field.p.String())
}
