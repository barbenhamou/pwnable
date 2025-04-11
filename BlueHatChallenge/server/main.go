package main

import (
	"blue-lockers/lls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
)

var (
	lockerNumberEnv  = os.Getenv("LOCKER_NUMBER")
	privateKeyEnv    = os.Getenv("PRIVATE_KEY")
)

func main() {
	if privateKeyEnv == "" {
		fmt.Println("PRIVATE_KEY environment variable not set")
		return
	}

	if lockerNumberEnv == "" {
		fmt.Println("LOCKER_NUMBER environment variable not set")
		return
	}

	privateKey, err := hex.DecodeString(privateKeyEnv)
	if err != nil {
		fmt.Println("Error decoding private key:", err)
		return
	}

	if len(privateKey) != 32 {
		fmt.Println("Private key must be 32 bytes")
		return
	}

	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Failed to start server:", err)
	}
	defer listener.Close()

	llsListener := lls.NewListener(listener, privateKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/open", func(w http.ResponseWriter, r *http.Request) {
		publicKey := r.Context().Value("publicKey").(*lls.Point)
		peerPublicKey := r.Context().Value("peerPublicKey").(*lls.Point)
		if !publicKey.Equals(peerPublicKey) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, "Unauthorized access")
			return
		}
		openLocker()
	})

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		publicKey := r.Context().Value("publicKey").(*lls.Point)
		peerPublicKey := r.Context().Value("peerPublicKey").(*lls.Point)
		publicKeyHex := hex.EncodeToString(publicKey.Bytes())
		peerPublicKeyHex := hex.EncodeToString(peerPublicKey.Bytes())
		fmt.Fprintln(w, "Welcome to the BlueHat locker system!")
		fmt.Fprintln(w, "Now protected with state of the art elliptic curve encryption, approved by the State Cryptography administration.")
		fmt.Fprintf(w, "Locker Number: %s\n", lockerNumberEnv)
		fmt.Fprintf(w, "Public Key: %s\n", publicKeyHex)
		fmt.Fprintf(w, "Peer Public Key: %s\n", peerPublicKeyHex)
	})

	server := &http.Server{
		Handler:     mux,
		ConnContext: lls.ConnContext,
	}

	fmt.Printf("Starting server at http://%s/\n", ":8080")
	// Define listener address and port (change this as needed)
	if err := server.Serve(llsListener); err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func openLocker() {
	f, err := os.OpenFile("/dev/locker0", os.O_WRONLY, 0)
	if err != nil {
		panic(err)
		fmt.Println("Error opening locker:", err)
		return
	}
	defer f.Close()

	f.Write([]byte("OPEN SESAME"))
}
