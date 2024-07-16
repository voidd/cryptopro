package cryptopro

import (
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func TestHash(t *testing.T) {
	prov, err := CryptAcquireContext("", "", PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := CreateCryptHash(prov, CALG_GR3411_2012_256)
	if err != nil {
		t.Fatal(err)
	}

	hashBytes, err := ioutil.ReadFile("hash.go")
	if err != nil {
		t.Fatal(err)
	}

	err = hash.CryptHashData(hashBytes)
	if err != nil {
		t.Fatal(err)
	}

	val, err := hash.CryptGetHashParam()
	if err != nil {
		t.Fatal(err)
	}
	hashVal := hex.EncodeToString(val)
	if hashVal != "c22c02217d212b8ab003a4e753b729a1793a5b43efc11095aa96a10628808714" {
		t.Fatal("got hash ", hashVal)
	}

	err = hash.DestoryHash()
	if err != nil {
		t.Fatal(err)
	}

	err = prov.Release()
	if err != nil {
		t.Fatal(err)
	}

}
