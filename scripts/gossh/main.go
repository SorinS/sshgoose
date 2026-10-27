// Go's golang.org/x/crypto/ssh as the other side, for scripts/gen_keys.py
// and the interop scripts:
//
//	gossh sign <private key file> <algorithm> <data hex>
//	    the signature blob (hex) of data by the key with that algorithm
//	gossh verify <public key line> <data hex> <signature blob hex>
//	    "ok" if the signature verifies, else the error
//	gossh pub <private key file>
//	    the key's authorized_keys line
//	gossh server <port> <host key file> <authorized_keys file> [password]
//	    an SSH server on 127.0.0.1: prints "ready", then for each session runs
//	    nothing but answers exec with "go ran: <command>", a line on stderr,
//	    and exit status 6; stdin is echoed back after EOF
//	gossh client <port> <user> <key file|-> <host key line> <command> [password]
//	    one connection running the command: prints its stdout and stderr, then
//	    "exit=<status>"; $GOSSH_KEX, $GOSSH_CIPHERS and $GOSSH_MACS set the
//	    algorithms (comma-separated)
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func algorithms(c *ssh.Config) {
	if v := os.Getenv("GOSSH_KEX"); v != "" {
		c.KeyExchanges = strings.Split(v, ",")
	}
	if v := os.Getenv("GOSSH_CIPHERS"); v != "" {
		c.Ciphers = strings.Split(v, ",")
	}
	if v := os.Getenv("GOSSH_MACS"); v != "" {
		c.MACs = strings.Split(v, ",")
	}
}

func serve(nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		fmt.Println("server error", err)
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for req := range creqs {
				switch req.Type {
				case "exec":
					var p struct{ Command string }
					ssh.Unmarshal(req.Payload, &p)
					req.Reply(true, nil)
					in, _ := io.ReadAll(ch)
					fmt.Fprintf(ch, "go ran: %s", p.Command)
					if len(in) > 0 {
						fmt.Fprintf(ch, " stdin=%d", len(in))
						ch.Write(in)
					}
					fmt.Fprintf(ch.Stderr(), "a line on stderr\n")
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{6}))
					return
				default:
					req.Reply(req.Type == "env" || req.Type == "pty-req", nil)
				}
			}
		}()
	}
}

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
	case "server":
		pem, err := os.ReadFile(os.Args[3])
		must(err)
		signer, err := ssh.ParsePrivateKey(pem)
		must(err)
		authText, err := os.ReadFile(os.Args[4])
		must(err)
		var allowed [][]byte
		for len(authText) > 0 {
			pub, _, _, rest, err := ssh.ParseAuthorizedKey(authText)
			if err != nil {
				break
			}
			allowed = append(allowed, pub.Marshal())
			authText = rest
		}
		cfg := &ssh.ServerConfig{
			PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
				for _, a := range allowed {
					if bytes.Equal(a, k.Marshal()) {
						return nil, nil
					}
				}
				return nil, errors.New("unknown key")
			},
		}
		if len(os.Args) > 5 {
			pw := os.Args[5]
			cfg.PasswordCallback = func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
				if string(p) == pw {
					return nil, nil
				}
				return nil, errors.New("wrong password")
			}
		}
		algorithms(&cfg.Config)
		cfg.AddHostKey(signer)
		ln, err := net.Listen("tcp", "127.0.0.1:"+os.Args[2])
		must(err)
		fmt.Println("ready")
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(nc, cfg)
		}
	case "client":
		hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(os.Args[5]))
		must(err)
		cfg := &ssh.ClientConfig{User: os.Args[3], HostKeyCallback: ssh.FixedHostKey(hostKey)}
		if os.Args[4] != "-" {
			pem, err := os.ReadFile(os.Args[4])
			must(err)
			signer, err := ssh.ParsePrivateKey(pem)
			must(err)
			cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
		}
		if len(os.Args) > 7 {
			cfg.Auth = append(cfg.Auth, ssh.Password(os.Args[7]))
		}
		algorithms(&cfg.Config)
		client, err := ssh.Dial("tcp", "127.0.0.1:"+os.Args[2], cfg)
		must(err)
		sess, err := client.NewSession()
		must(err)
		var stdout, stderr bytes.Buffer
		sess.Stdout = &stdout
		sess.Stderr = &stderr
		sess.Stdin = os.Stdin
		err = sess.Run(os.Args[6])
		status := 0
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			status = ee.ExitStatus()
		} else if err != nil {
			must(err)
		}
		fmt.Print(stdout.String())
		fmt.Print(stderr.String())
		fmt.Printf("exit=%d\n", status)
		client.Close()
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
