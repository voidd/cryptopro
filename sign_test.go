package cryptopro

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCryptSignHash(t *testing.T) {

	capBytes := []byte("Hello world")

	store, err := CertOpenSystemStore("MY")
	defer CertCloseStore(store, 0)
	if err != nil {
		t.Fatal("Can't open MY store")
	}

	client, err := CertFindCertificateInStore(store, "a0dbdc9a9cc0fcafcbb6161f603ff7d5c4d7b548",
		CERT_FIND_SHA1_HASH)
	defer CertFreeCertificateContext(client)
	if err != nil {
		t.Fatal(err)
	}

	context, err := CryptAquireCertificatePrivateKey(client)
	defer context.Release()
	if err != nil {
		t.Fatal(err)
	}

	hash, err := CreateCryptHash(context, CALG_GR3411)
	defer hash.DestoryHash()
	if err != nil {
		t.Fatal(err)
	}

	err = hash.CryptHashData(capBytes)
	if err != nil {
		t.Fatal(err)
	}

	_, err = hash.CryptGetHashParam()
	if err != nil {
		t.Fatal(err)
	}

	sigBytes, err := CryptSignHash(hash, AT_KEYEXCHANGE, 0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("signature: %s\n", hex.EncodeToString(sigBytes))

}
