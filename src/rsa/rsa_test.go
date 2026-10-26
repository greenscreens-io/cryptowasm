package rsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestGenerateKeyRejectsUnsupportedExponent(t *testing.T) {
	if _, err := GenerateKey(1024, 3); err == nil {
		t.Fatal("expected unsupported public exponent to be rejected")
	}
}

func TestGenerateKeyUsesConsistentDefaultExponent(t *testing.T) {
	id, err := GenerateKey(1024, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer RemoveKey(id, false)

	privateKey := rsaCache.Private.Get(id)
	if privateKey == nil {
		t.Fatal("generated private key was not cached")
	}
	if privateKey.E != 65537 || privateKey.PublicKey.E != 65537 {
		t.Fatalf("generated keypair exponent mismatch: private public exponent=%d, public exponent=%d", privateKey.E, privateKey.PublicKey.E)
	}
	if err := privateKey.Validate(); err != nil {
		t.Fatalf("generated keypair is invalid: %v", err)
	}
}

func TestRemoveKeyActuallyRemovesRSAKey(t *testing.T) {
	id, err := GenerateKey(1024, 65537)
	if err != nil {
		t.Fatal(err)
	}

	if !RemoveKey(id, false) {
		t.Fatal("expected private-key removal to succeed")
	}
	if HasKey(id, false) || HasKey(id, true) {
		t.Fatal("removing the private key should also remove its paired public key")
	}
	if RemoveKey(id, false) {
		t.Fatal("removing an already removed key should fail")
	}
}

func TestMalformedPEMReturnsError(t *testing.T) {
	if _, err := decodePrivKey("not PEM"); err == nil {
		t.Fatal("expected malformed private-key PEM to return an error")
	}
	if _, err := decodePubKey("not PEM"); err == nil {
		t.Fatal("expected malformed public-key PEM to return an error")
	}
}

func TestWrongKeyTypesReturnErrors(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodePrivKeyRaw(privateDER); err == nil {
		t.Fatal("RSA private-key decoder accepted an Ed25519 key")
	}
	if _, err := decodePubKeyRaw(publicDER); err == nil {
		t.Fatal("RSA public-key decoder accepted an Ed25519 key")
	}
}
