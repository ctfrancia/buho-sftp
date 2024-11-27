package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	authorizedKeysPath = "internal/keys/authorized_keys"
)

func main() {
	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		/*
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				// Should use constant-time compare (or better, salt+hash) in
				// a production setting.
				if c.User() == "testuser" && string(pass) == "tiger" {
					return nil, nil
				}
				return nil, fmt.Errorf("password rejected for %q", c.User())
			},
		*/

		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(private)
	// TODO: https://pkg.go.dev/github.com/pkg/sftp#example-package
	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	defer listener.Close()

	for {
		// Accept connections
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}

		// Handshake
		serverConn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			log.Printf("failed to handshake: %v", err)
			continue
		}

		// Discard all global out-of-band requests
		go ssh.DiscardRequests(reqs)

		// Handle incoming channels (SSH channels are used for interactive sessions or SFTP)
		for ch := range chans {
			go handleChannel(serverConn, ch)
		}

	}
}

// handleChannel processes a single channel (for SFTP file transfers)
func handleChannel(serverConn *ssh.ServerConn, ch ssh.NewChannel) {
	// Accept the channel
	channel, _, err := ch.Accept()
	if err != nil {
		log.Printf("failed to accept channel: %v", err)
		return
	}
	defer channel.Close()

	// Start an SFTP server on this channel
	client, err := sftp.NewServer(channel)
	if err != nil {
		log.Printf("failed to start SFTP server: %v", err)
		return
	}
	defer client.Close()

	// The server automatically processes requests (like WRITE for file upload)
	// so no need to manually handle requests.
	if err := client.Serve(); err != nil {
		log.Printf("failed to serve SFTP requests: %v", err)
		return
	}

	log.Println("SFTP session ended successfully")
}
