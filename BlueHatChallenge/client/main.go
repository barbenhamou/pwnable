package main

import (
	"blue-lockers/lls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

var (
	privateKeyEnv = os.Getenv("PRIVATE_KEY")
)

func main() {
	if privateKeyEnv == "" {
		fmt.Println("PRIVATE_KEY environment variable not set")
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

	dialer := lls.NewDialer(net.Dialer{}, privateKey)

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	fmt.Println("Sending request ")
	resp, err := client.Get("http://localhost:8080/info")
	if err != nil {
		fmt.Println("Error sending request", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("Response:", resp.Status)
	fmt.Println("Body:")
	_, err = io.Copy(os.Stdout, resp.Body)

}
