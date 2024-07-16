package cryptopro

import (
	"testing"
)

func TestCryptExportPublicKey(t *testing.T) {
	store, err := CertOpenSystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}

	cert, err := CertFindCertificateInStore(store, "a0dbdc9a9cc0fcafcbb6161f603ff7d5c4d7b548", CERT_FIND_SHA1_HASH)
	if err != nil {
		t.Fatal(err)
	}

	prov, err := CryptAquireCertificatePrivateKey(cert)
	if err != nil {
		t.Fatal(err)
	}

	key, err := CryptGetUserKey(prov, AT_KEYEXCHANGE)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := CryptExportKey(key, PUBLICKEYBLOB)
	if err != nil {
		t.Fatal(err)
	}

	_, err = CryptImportKey(prov, blob)
	if err != nil {
		t.Fatal(err)
	}

	err = CertFreeCertificateContext(cert)
	if err != nil {
		t.Fatal(err)
	}

	err = CertCloseStore(store, 0)
	if err != nil {
		t.Fatal(err)
	}

	err = prov.Release()
	if err != nil {
		t.Fatal(err)
	}
}
