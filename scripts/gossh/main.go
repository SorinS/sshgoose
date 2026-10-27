// Go's golang.org/x/crypto/ssh as the other side, for scripts/gen_keys.py
// and the interop scripts:
//
//	gossh sign <private key file> <algorithm> <data hex>
//	    the signature blob (hex) of data by the key with that algorithm
//	gossh verify <public key line> <data hex> <signature blob hex>
//	    "ok" if the signature verifies, else the error
//	gossh pub <private key file>
//	    the key's authorized_keys line
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func must(err error) {
	if err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
}

func main() {
	switch os.Args[1] {
	case "sign":
		pem, err := os.ReadFile(os.Args[2])
		must(err)
		signer, err := ssh.ParsePrivateKey(pem)
		must(err)
		data, _ := hex.DecodeString(os.Args[4])
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			must(fmt.Errorf("not an AlgorithmSigner"))
		}
		sig, err := as.SignWithAlgorithm(rand.Reader, data, os.Args[3])
		must(err)
		fmt.Println(hex.EncodeToString(ssh.Marshal(sig)))
	case "pub":
		pem, err := os.ReadFile(os.Args[2])
		must(err)
		signer, err := ssh.ParsePrivateKey(pem)
		must(err)
		fmt.Print(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	case "verify":
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Args[2]))
		must(err)
		data, _ := hex.DecodeString(os.Args[3])
		raw, _ := hex.DecodeString(os.Args[4])
		var sig ssh.Signature
		must(ssh.Unmarshal(raw, &sig))
		must(pub.Verify(data, &sig))
		fmt.Println("ok")
	}
}
