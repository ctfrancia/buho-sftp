package main

import (
	"fmt"
	"io"
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
}

/*
func main() {
	var (
		readOnly    bool
		debugStderr bool
	)

	flag.BoolVar(&readOnly, "R", false, "read-only server")
	flag.BoolVar(&debugStderr, "e", true, "debug to stderr")
	flag.Parse()

	debugStream := io.Discard
	if debugStderr {
		debugStream = os.Stderr
	}

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
	config, err := generateSSHServerConfig(authorizedKeysMap)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("failed to listen for connection", err)
	}
	fmt.Printf("Listening on %v\n", listener.Addr())

	defer listener.Close()

	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake", err)
	}
	fmt.Fprintf(debugStream, "SSH server established\n")

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of an SFTP session, this is "subsystem"
		// with a payload string of "<length=4>sftp"
		fmt.Fprintf(debugStream, "Incoming channel: %s\n", newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			fmt.Fprintf(debugStream, "Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatal("could not accept channel.", err)
		}
		fmt.Fprintf(debugStream, "Channel accepted\n")

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "subsystem" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				fmt.Fprintf(debugStream, "Request: %v\n", req.Type)
				ok := false
				switch req.Type {
				case "subsystem":
					fmt.Fprintf(debugStream, "Subsystem: %s\n", req.Payload[4:])
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
				fmt.Fprintf(debugStream, " - accepted: %v\n", ok)
				req.Reply(ok, nil)
			}
		}(requests)

		serverOptions := []sftp.ServerOption{
			sftp.WithDebug(debugStream),
		}

		if readOnly {
			serverOptions = append(serverOptions, sftp.ReadOnly())
			fmt.Fprintf(debugStream, "Read-only server\n")
		} else {
			fmt.Fprintf(debugStream, "Read write server\n")
		}

		fmt.Fprintf(debugStream, "Starting sftp server %#v", serverOptions)

		server, err := sftp.NewServer(
			channel,
			serverOptions...,
		)
		if err != nil {
			log.Fatal(err)
		}
		if err := server.Serve(); err != nil {
			if err != io.EOF {
				log.Fatal("sftp server completed with error:", err)
			}
		}
		server.Close()
		log.Print("sftp client exited session.")
	}
}
*/

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
		log.Fatal("failed to generate SSH server config: ", err)
		return
	}

	log.Printf("SSH server started on %s", address)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		// Perform SSH handshake
		_, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("failed to handshake: %v", err)
			tcpConn.Close()
			continue
		}

		log.Printf("Accepted SSH connection from %s", tcpConn.RemoteAddr())

		// Handle the incoming SSH requests and channels
		go handleSFTPSession(chans, reqs)
	}
}

// Handle an SFTP session over SSH
func handleSFTPSession(chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	for newChannel := range chans {
		// Only accept 'session' channels (these are used for SFTP)
		fmt.Printf("Incoming channel: %s\n", newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			fmt.Fprintf(os.Stdout, "Unknown channel type: %s\n", newChannel.ChannelType())
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel: %v", err)
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				fmt.Fprintf(os.Stdout, "Request: %v\n", req.Type)
				ok := false
				switch req.Type {
				case "subsystem":
					fmt.Fprintf(os.Stdout, "Subsystem: %s\n", req.Payload[4:])
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
				fmt.Fprintf(os.Stdout, " - accepted: %v\n", ok)
				req.Reply(ok, nil)
			}
		}(requests)

		// Handle SFTP request over the channel
		handleSFTPRequest(channel)
	}
}

// Handle the SFTP subsystem on the channel
func handleSFTPRequest(channel ssh.Channel) {
	// Start an SFTP server over this channel
	serveroptions := []sftp.ServerOption{
		sftp.WithDebug(os.Stdout),
	}
	sftpServer, err := sftp.NewServer(channel, serveroptions...)
	if err != nil {
		log.Printf("Failed to start SFTP server: %v", err)
		return
	}

	defer sftpServer.Close()

	// Serve the requests
	if err := sftpServer.Serve(); err != nil {
		if err != io.EOF {
			log.Fatal("sftp server completed with error:", err)
		}
		log.Printf("SFTP server error: %v", err)
	}
	sftpServer.Close()
}
