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
	address            = "0.0.0.0:2022"
)

// Handle an SFTP session over SSH
func handleSFTPSession(conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	for newChannel := range chans {
		// Only accept 'session' channels (these are used for SFTP)
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, _, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel: %v", err)
			continue
		}

		// Handle SFTP request over the channel
		handleSFTPRequest(channel)
	}
}

// Handle the SFTP subsystem on the channel
func handleSFTPRequest(channel ssh.Channel) {
	// Start an SFTP server over this channel
	sftpServer, err := sftp.NewServer(channel)
	if err != nil {
		log.Printf("Failed to start SFTP server: %v", err)
		return
	}
	defer sftpServer.Close()

	// Serve the requests
	if err := sftpServer.Serve(); err != nil {
		log.Printf("SFTP server error: %v", err)
	}
}

// Generate the SSH server configuration (with public key authentication)
func generateSSHServerConfig(authorizedKeysMap map[string]bool) (*ssh.ServerConfig, error) {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
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

	// Load the private key for the SSH server
	privateBytes, err := os.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(private)
	return config, nil
	/*
		// Load the private key for the SSH server
		privateBytes, err := os.ReadFile("server_id_rsa")
		if err != nil {
			return nil, fmt.Errorf("unable to load private key: %v", err)
		}
		privateKey, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}

		// Create the SSH server configuration
		serverConfig := &ssh.ServerConfig{
			NoClientAuth: false, // We will authenticate using public key
		}
		serverConfig.AddHostKey(privateKey)

		return serverConfig, nil
	*/
}

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

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	defer listener.Close()
	// Generate the SSH server configuration
	config, err := generateSSHServerConfig(authorizedKeysMap)
	if err != nil {
		return // fmt.Errorf("failed to generate SSH server config: %v", err)
	}

	log.Printf("SSH server started on %s", address)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
			continue
		}
		// Perform SSH handshake
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("failed to handshake: %v", err)
			tcpConn.Close()
			continue
		}

		log.Printf("Accepted SSH connection from %s", tcpConn.RemoteAddr())

		// Handle the incoming SSH requests and channels
		go handleSFTPSession(sshConn, chans, reqs)
	}
}
