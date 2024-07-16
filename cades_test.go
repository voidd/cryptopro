package cryptopro

import (
	"fmt"
	"testing"
)

func TestCadesBes(t *testing.T) {
	thumbprint := "a0dbdc9a9cc0fcafcbb6161f603ff7d5c4d7b548"
	file := []byte("test msg")

	// открываем хранилище
	store, err := CertOpenSystemStore("MY")
	defer func() {
		if err = CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG); err != nil {
			fmt.Printf("close store failed: %s\n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("open MY store failed: %w", err))
	}

	// поиск сертификата
	cert, err := CertFindCertificateInStore(store, thumbprint, CERT_FIND_SHA1_HASH)
	defer func() {
		if err = CertFreeCertificateContext(cert); err != nil {
			fmt.Printf("free certificate context failed: %s\n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("find certificate in store failed: %w", err))
	}

	// проверка наличия закрытого ключа
	prov, err := CryptAquireCertificatePrivateKey(cert)
	defer func() {
		if err = prov.Release(); err != nil {
			fmt.Printf("release context failed: %s \n", err.Error())
		}
	}()
	if err != nil {
		t.Fatal(fmt.Errorf("get private key failed: %w", err))
	}

	hash, err := CreateCryptHash(prov, CALG_GR3411_2012_256)
	if err != nil {
		t.Fatal(err)
	}

	err = hash.CryptHashData(file)
	if err != nil {
		t.Fatal(err)
	}

	val, err := hash.CryptGetHashParam()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("byte array:\t %v \n hash value: \t %x \n", file, val)

	_, err = SignMessageCadesXlt(cert, val)
	if err != nil {
		t.Fatal(fmt.Errorf("sign message failed: %w", err))
	}
}
