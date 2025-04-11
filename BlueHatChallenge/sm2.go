package lls

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	// Weierstrass curve parameters for SM2
	// p = 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
	// a = 0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc
	// b = 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
	// G = (0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
	//      0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0)
	// n = 0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123
	P  = [32]byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	A  = [32]byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc}
	B  = [32]byte{0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e, 0x4b, 0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab, 0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93}
	GX = [32]byte{0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04, 0x46, 0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66, 0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7}
	GY = [32]byte{0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce, 0xe3, 0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a, 0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0}
	N  = [32]byte{0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23}
)

type SM2 struct {
	field *GaloisField
}

func NewSM2() *SM2 {
	return &SM2{
		field: NewGaloisField(*big.NewInt(0).SetBytes(P[:])),
	}
}

func (sm2 *SM2) NewPoint(x, y big.Int) *Point {
	return &Point{
		x:   sm2.field.NewElement(x),
		y:   sm2.field.NewElement(y),
		sm2: sm2,
	}
}

// ZeroPoint returns the identity point (0, 0)
func (sm2 *SM2) ZeroPoint() *Point {
	return &Point{
		x:   sm2.field.NewElement(*big.NewInt(0)),
		y:   sm2.field.NewElement(*big.NewInt(0)),
		sm2: sm2,
	}
}

func (sm2 *SM2) Generator() *Point {
	return sm2.NewPoint(
		*big.NewInt(0).SetBytes(GX[:]), *big.NewInt(0).SetBytes(GY[:]),
	)
}

func (sm2 *SM2) a() *GaloisFieldElement {
	return sm2.field.NewElement(
		*big.NewInt(0).SetBytes(A[:]),
	)
}

func (sm2 *SM2) b() *GaloisFieldElement {
	return sm2.field.NewElement(
		*big.NewInt(0).SetBytes(B[:]),
	)
}

type ECDH struct {
	sm2        *SM2
	PrivateKey big.Int
}

func (sm2 *SM2) NewECDH(privateKey big.Int) *ECDH {
	return &ECDH{
		sm2:        sm2,
		PrivateKey: privateKey,
	}
}

func (ecdh *ECDH) GetPublicKey() *Point {
	return ecdh.sm2.Generator().ScalarMul(&ecdh.PrivateKey)
}

func (ecdh *ECDH) GenerateSharedSecret(publicKey *Point) [32]byte {
	// Return SHA256 of (x, y) coordinates of the shared secret
	sharedPoint := publicKey.ScalarMul(&ecdh.PrivateKey)
	return sha256.Sum256([]byte(sharedPoint.String()))
}

type ECDSA struct {
	sm2        *SM2
	PrivateKey big.Int
}

func (sm2 *SM2) NewECDSA(privateKey big.Int) *ECDSA {
	return &ECDSA{
		sm2:        sm2,
		PrivateKey: privateKey,
	}
}

func (ecdsa *ECDSA) GetPublicKey() *Point {
	return ecdsa.sm2.Generator().ScalarMul(&ecdsa.PrivateKey)
}

func (ecdsa *ECDSA) Sign(message []byte) (*big.Int, *big.Int) {
	n := new(big.Int).SetBytes(N[:])
	// Return SHA256 of (x, y) coordinates of the shared secret
	Hm := sha256.Sum256(message)
	z := new(big.Int).SetBytes(Hm[:32])

	var k, r *big.Int
	for {
		var err error
		k, err = rand.Int(rand.Reader, n)
		if err != nil {
			panic("failed to generate random number")
		}
		r_Point := ecdsa.sm2.Generator().ScalarMul(k)
		r = &r_Point.x.Int
		r.Mod(r, n)
		if r.Cmp(big.NewInt(0)) == 0 {
			// If r = 0, then choose another random k
			continue
		}
		// Otherwise were done
		break
	}

	r_dA := new(big.Int).Mul(r, &ecdsa.PrivateKey)
	z_r_dA := new(big.Int).Add(z, r_dA)
	k_Inverse := new(big.Int).ModInverse(k, n)
	if k_Inverse == nil {
		panic("failed to sign, k has no inverse modulo n")
	}
	s := new(big.Int).Mul(z_r_dA, k_Inverse)
	s.Mod(s, n)

	return r, s
}

func (ecdsa *ECDSA) Verify(message []byte, publicKey Point, r, s big.Int) bool {
	n := new(big.Int).SetBytes(N[:])
	Hm := sha256.Sum256(message)
	z := new(big.Int).SetBytes(Hm[:32])
	s_Inverse := new(big.Int).ModInverse(&s, n)

	u1 := new(big.Int).Mul(z, s_Inverse)
	u1.Mod(u1, n)

	u2 := new(big.Int).Mul(&r, s_Inverse)
	u2.Mod(u2, n)

	u1_G := ecdsa.sm2.Generator().ScalarMul(u1)
	u2_qA := publicKey.ScalarMul(u2)

	res := u1_G.Add(u2_qA)
	if big.NewInt(0).Mod(&r, n).Cmp(&res.x.Int) == 0 {
		return true
	}

	return false
}
