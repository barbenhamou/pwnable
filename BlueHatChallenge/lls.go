package lls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LLS Protocol - elliptic curve Locker Layer Security (SM2)
// On new connection perform the following handshake:
// 1. Establish secure channel using ECDH
// 2. Apply AES-CTR encryption using shared secret
// 3. Exchange signature blocks for authentication
// 4. Done! Locker Layer Security connection established

// Conn
type Conn struct {
	baseConn       net.Conn
	encryptStream  cipher.Stream
	decryptStream  cipher.Stream
	readMutex      sync.Mutex
	writeMutex     sync.Mutex
	handshakeFn    func() error
	handshakeMutex sync.Mutex
	handshakeError error
	handshakeDone  atomic.Bool
	privateKey     []byte
	peerPublicKey  Point
}

func (c *Conn) LocalAddr() net.Addr {
	return c.baseConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.baseConn.RemoteAddr()
}

func (c *Conn) PublicKey() *Point {
	sm2 := NewSM2()
	ecdsa := sm2.NewECDSA(*big.NewInt(0).SetBytes(c.privateKey))
	return ecdsa.GetPublicKey()
}

func (c *Conn) PeerPublicKey() *Point {
	return &c.peerPublicKey
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.baseConn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.baseConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.baseConn.SetWriteDeadline(t)
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	n, err := c.baseConn.Read(b)
	if err != nil {
		return 0, err
	}

	c.decryptStream.XORKeyStream(b[:n], b[:n])
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	c.encryptStream.XORKeyStream(b, b)
	return c.baseConn.Write(b)
}

func (c *Conn) Close() error {
	return c.baseConn.Close()
}

func (c *Conn) Handshake() error {
	if c.handshakeDone.Load() {
		return nil
	}

	if c.handshakeFn == nil {
		panic("Handshake function not set")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeFn(); err != nil {
		return err
	}

	if c.handshakeDone.Load() {
		return nil
	}

	c.handshakeError = c.handshakeFn()

	return c.handshakeError

}
func (c *Conn) clientHandshake() error {
	var Qserver_bytes [64]byte
	sm2 := NewSM2()
	ecdh := sm2.NewECDH(*big.NewInt(0).SetBytes(c.privateKey))
	ecdsa := sm2.NewECDSA(*big.NewInt(0).SetBytes(c.privateKey))

	// Send public key Qclient to server
	Qclient := ecdh.GetPublicKey()
	_, err := c.baseConn.Write(Qclient.Bytes())
	if err != nil {
		return err
	}

	// Receive public key Qserver from server
	_, err = c.baseConn.Read(Qserver_bytes[:])
	if err != nil {
		return err
	}

	// Parse Qserver
	Qserver_x := new(big.Int).SetBytes(Qserver_bytes[:32])
	Qserver_y := new(big.Int).SetBytes(Qserver_bytes[32:])
	Qserver := ecdh.sm2.NewPoint(*Qserver_x, *Qserver_y)

	// Establish shared secret
	sharedSecret := ecdh.GenerateSharedSecret(Qserver)

	// Derive into AES key
	streamKey := sharedSecret[:]

	block, err := aes.NewCipher(streamKey[:])
	if err != nil {
		return err
	}

	// Receive nonce from server
	nonce := make([]byte, aes.BlockSize)
	_, err = c.baseConn.Read(nonce)
	if err != nil {
		return err
	}

	c.encryptStream = cipher.NewCTR(block, nonce)
	c.decryptStream = cipher.NewCTR(block, nonce)

	// Secure channel established, now authenticate the connection
	// Receive signature block from server
	toSignServer := []byte("LlsServerHello:")
	signatureBlockServer := make([]byte, len(toSignServer)+64)
	_, err = c.baseConn.Read(signatureBlockServer[:])
	if err != nil {
		return fmt.Errorf("clientHandshake: Failed to read signature block: %v", err)
	}

	// Decrypt signature block
	c.decryptStream.XORKeyStream(signatureBlockServer, signatureBlockServer)

	if !bytes.HasPrefix(signatureBlockServer, toSignServer) {
		return errors.New("clientHandshake: Invalid signature block")
	}

	// Trim prefix
	copy(signatureBlockServer, signatureBlockServer[len(toSignServer):])

	var serverNonce, serverSignature [32]byte
	copy(serverNonce[:], reverseBytes(signatureBlockServer[0:32]))
	copy(serverSignature[:], reverseBytes(signatureBlockServer[32:64]))

	// Parse server nonce and signature
	serverNonceInt := new(big.Int).SetBytes(serverNonce[:])
	serverSignatureInt := new(big.Int).SetBytes(serverSignature[:])

	// And verify them using Qserver
	if !ecdsa.Verify(toSignServer, *Qserver, *serverNonceInt, *serverSignatureInt) {
		return errors.New("clientHandshake: Failed to authenticate server")
	}

	c.peerPublicKey = *Qserver

	// Generate signature block for Qclient
	toSignClient := []byte("LlsClientHello:")
	clientNonceInt, clientSignatureInt := ecdsa.Sign(toSignClient)

	signatureBlockClient := make([]byte, 64)

	// Set into network order
	copy(signatureBlockClient[0:32], reverseBytes(clientNonceInt.Bytes()))
	copy(signatureBlockClient[32:64], reverseBytes(clientSignatureInt.Bytes()))

	signatureBlockClient = append(toSignClient, signatureBlockClient...)

	// Encrypt signature block
	c.encryptStream.XORKeyStream(signatureBlockClient[:], signatureBlockClient[:])

	// And send it to server
	_, err = c.baseConn.Write(signatureBlockClient[:])
	if err != nil {
		return fmt.Errorf("Failed to write signature block: %v", err)
	}

	c.handshakeDone.Store(true)
	return nil
}

func (c *Conn) serverHandshake() error {
	// Receive public key Qclient from client
	var Qclient_bytes [64]byte
	sm2 := NewSM2()
	ecdh := sm2.NewECDH(*big.NewInt(0).SetBytes(c.privateKey))
	ecdsa := sm2.NewECDSA(*big.NewInt(0).SetBytes(c.privateKey))

	_, err := c.baseConn.Read(Qclient_bytes[:])
	if err != nil {
		return err
	}

	// Send public key Qserver to client
	Qserver := ecdh.GetPublicKey()
	_, err = c.baseConn.Write(Qserver.Bytes())
	if err != nil {
		return err
	}

	// Parse Qclient
	Qclient_x := new(big.Int).SetBytes(Qclient_bytes[:32])
	Qclient_y := new(big.Int).SetBytes(Qclient_bytes[32:])
	Qclient := ecdh.sm2.NewPoint(*Qclient_x, *Qclient_y)

	// Establish shared secret
	sharedSecret := ecdh.GenerateSharedSecret(Qclient)

	// Derive into AES key
	streamKey := sharedSecret[:]

	block, err := aes.NewCipher(streamKey[:])
	if err != nil {
		return err
	}

	// Generate nonce and send to client
	nonce := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, nonce)

	_, err = c.baseConn.Write(nonce)
	if err != nil {
		return err
	}

	c.encryptStream = cipher.NewCTR(block, nonce)
	c.decryptStream = cipher.NewCTR(block, nonce)

	// Secure channel established, now authenticate the connection
	// Generate signature block for "LlsServerHello"
	toSignServer := []byte("LlsServerHello:")
	serverNonceInt, serverSignatureInt := ecdsa.Sign(toSignServer)

	signatureBlockServer := make([]byte, 64)

	copy(signatureBlockServer[0:32], reverseBytes(serverNonceInt.Bytes()))
	copy(signatureBlockServer[32:64], reverseBytes(serverSignatureInt.Bytes()))

	signatureBlockServer = append(toSignServer, signatureBlockServer...)

	// Encrypt signature block
	c.encryptStream.XORKeyStream(signatureBlockServer[:], signatureBlockServer[:])

	// And send it
	_, err = c.baseConn.Write(signatureBlockServer[:])
	if err != nil {
		return fmt.Errorf("serverHandshake: Failed to write signature block: %v", err)
	}

	toSignClient := []byte("LlsClientHello:")
	// Authenticate the client, receive signature block
	signatureBlockClient := make([]byte, len(toSignClient)+64)
	_, err = c.baseConn.Read(signatureBlockClient[:])
	if err != nil {
		return fmt.Errorf("serverHandshake: Failed to read signature block: %v", err)
	}

	// Decrypt signature block
	c.decryptStream.XORKeyStream(signatureBlockClient, signatureBlockClient)

	if !bytes.HasPrefix(signatureBlockClient, toSignClient) {
		return errors.New("serverHandshake: Invalid signature block")
	}

	// Trim
	copy(signatureBlockClient, signatureBlockClient[len(toSignClient):])

	var clientNonce, clientSignature [32]byte
	// Set into host order
	copy(clientNonce[:], reverseBytes(signatureBlockClient[0:32]))
	copy(clientSignature[:], reverseBytes(signatureBlockClient[32:64]))

	clientNonceInt := new(big.Int).SetBytes(clientNonce[:])
	clientSignatureInt := new(big.Int).SetBytes(clientSignature[:])

	// And verify
	if !ecdsa.Verify(toSignClient, *Qclient, *clientNonceInt, *clientSignatureInt) {
		return errors.New("serverHandshake: Failed to authenticate client")
	}

	c.peerPublicKey = *Qclient

	// handshake done
	c.handshakeDone.Store(true)
	return nil
}

// Listener
type Listener struct {
	baseListener net.Listener
	privateKey   []byte
}

func NewListener(l net.Listener, privateKey []byte) *Listener {
	return &Listener{
		baseListener: l,
		privateKey:   privateKey,
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.baseListener.Accept()
	if err != nil {
		return nil, err
	}

	c := &Conn{
		baseConn:   conn,
		privateKey: l.privateKey,
	}
	c.handshakeFn = c.serverHandshake

	return c, nil
}

func (l *Listener) PublicKey() *Point {
	sm2 := NewSM2()
	ecdsa := sm2.NewECDSA(*big.NewInt(0).SetBytes(l.privateKey))
	return ecdsa.GetPublicKey()
}

func (l *Listener) Close() error {
	return l.baseListener.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.baseListener.Addr()
}

// Dialer
type Dialer struct {
	baseDialer net.Dialer
	privateKey []byte
}

func NewDialer(baseDialer net.Dialer, privateKey []byte) *Dialer {
	return &Dialer{
		baseDialer: baseDialer,
		privateKey: privateKey,
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dial(network, address)
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	// Dial to LLS server using regular conn
	conn, err := d.baseDialer.Dial(network, address)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		baseConn:   conn,
		privateKey: d.privateKey,
	}

	c.handshakeFn = c.clientHandshake

	c.handshakeFn()
	return c, nil
}

// Utilities
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	// Utility for injecting the public keys into the context
	if llsConn, ok := c.(*Conn); ok {
		ctx1 := context.WithValue(ctx, "publicKey", llsConn.PublicKey())
		return context.WithValue(ctx1, "peerPublicKey", llsConn.PeerPublicKey())
	}
	return ctx
}

func reverseBytes(b []byte) []byte {
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}

	return b
}
