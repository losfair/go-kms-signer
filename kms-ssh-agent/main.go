package main

import (
	"io"
	"log"
	"net"
	"os"
	"strings"

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
