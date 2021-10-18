package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/glassechidna/go-kms-signer/kms-ssh-agent/kmsagent"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	keyId := os.Getenv("KMS_KEY_ID")
	if keyId == "" {
		log.Fatalln("KMS_KEY_ID environment variable not set")
	}

	sess := session.Must(session.NewSession())
	api := kms.New(sess)

	pubresp, err := api.GetPublicKey(&kms.GetPublicKeyInput{KeyId: &keyId})
	if err != nil {
		log.Fatalf("GetPublicKey error: %+v\n", err)
	}

	key, err := kmssigner.ParseCryptoKey(pubresp)
	if err != nil {
		log.Fatalf("ParseCryptoKey error: %+v\n", err)
	}

	sshkey, err := ssh.NewPublicKey(key)
	if err != nil {
		log.Fatalf("NewPublicKey error: %+v\n", err)
	}

	authorized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshkey))) + " kms-" + keyId
	log.Printf("SSH public key: \n%s\n", string(authorized))

	keyType := sshkey.Type()
	var signMode kmssigner.Mode
	if keyType == "ssh-rsa" {
		signMode = kmssigner.ModeRsaPkcs1v15
	} else if strings.HasPrefix(keyType, "ecdsa-sha2-") {
		signMode = kmssigner.ModeEcdsa
	} else {
		log.Fatalf("unsupported key type: %s\n", keyType)
	}

	listenSock := os.Getenv("AGENT_LISTEN_SOCK")

	args := os.Args
	if len(args) > 1 {
		if listenSock != "" {
			panic("cannot specify both AGENT_LISTEN_SOCK and arguments")
		}

		listenSockDir, err := os.MkdirTemp("", "kms-ssh-agent-")
		if err != nil {
			panic(err)
		}
		listenSock = path.Join(listenSockDir, "service.sock")
		defer os.RemoveAll(listenSockDir)

		lis, err := net.Listen("unix", listenSock)
		if err != nil {
			panic(err)
		}
		os.Setenv("SSH_AUTH_SOCK", listenSock)
		cmd := exec.Command(args[1], args[2:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.SysProcAttr = &syscall.SysProcAttr{Foreground: true, Setpgid: true, Pdeathsig: syscall.SIGHUP}
		err = cmd.Start()
		if err != nil {
			// Use panic to ensure that `defer` is run
			panic(fmt.Sprintf("unable to start command: %+v\n", err))
		}

		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("error in service thread: %+v\n", err)
				}
				os.RemoveAll(listenSockDir)
				os.Exit(0)
			}()
			serve(lis, api, signMode, keyId)
		}()

		err = cmd.Wait()
		if err != nil {
			switch e := err.(type) {
			case *exec.ExitError:
				// defer will no longer run
				os.RemoveAll(listenSockDir)
				os.Exit(e.ExitCode())
			default:
				panic(fmt.Sprintf("wait command failed: %+v\n", err))
			}
		}
	} else {
		if listenSock == "" {
			log.Println("Exiting because the AGENT_LISTEN_SOCK environment variable is not set.")
			os.Exit(0)
		}

		os.Remove(listenSock)
		lis, err := net.Listen("unix", listenSock)
		if err != nil {
			panic(err)
		}
		err = serve(lis, api, signMode, keyId)
		if err != nil {
			panic(err)
		}
	}
}

func serve(lis net.Listener, api kmsiface.KMSAPI, mode kmssigner.Mode, keyId string) error {
	signer := kmssigner.New(api, keyId, mode)

	kmsag, err := kmsagent.New([]*kmssigner.Signer{signer})
	if err != nil {
		panic(err)
	}

	for {
		conn, err := lis.Accept()
		if err != nil {
			panic(err)
		}

		err = agent.ServeAgent(kmsag, conn)
		if err != nil && err != io.EOF {
			panic(err)
		}
	}
}
