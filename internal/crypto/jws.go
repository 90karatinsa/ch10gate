package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

type JWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func SignDetachedJWS(payload []byte, privateKeyPEM []byte) (JWS, error) {
	hdr := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	hb, _ := json.Marshal(hdr)
	protected := base64.RawURLEncoding.EncodeToString(hb)
	pl := base64.RawURLEncoding.EncodeToString(payload)

	priv, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return JWS{}, err
	}

	signingInput := protected + "." + pl
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return JWS{}, err
	}

	return JWS{
		Protected: protected,
		Payload:   pl,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no pem block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func VerifyDetachedJWS(payload []byte, jws JWS, certPEM []byte) error {
	if jws.Protected == "" || jws.Payload == "" || jws.Signature == "" {
		return errors.New("jws missing fields")
	}

	expectedPayload := base64.RawURLEncoding.EncodeToString(payload)
	if subtle.ConstantTimeCompare([]byte(expectedPayload), []byte(jws.Payload)) != 1 {
		return errors.New("payload does not match manifest bytes")
	}

	protectedBytes, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return fmt.Errorf("decode protected header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(protectedBytes, &header); err != nil {
		return fmt.Errorf("unmarshal protected header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported alg %q", header.Alg)
	}

	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	pub, err := parseRSAPublicKey(certPEM)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	signingInput := jws.Protected + "." + jws.Payload
	h := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no pem block")
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("certificate public key is not RSA")
		}
		return pub, nil
	}

	if pubAny, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if pub, ok := pubAny.(*rsa.PublicKey); ok {
			return pub, nil
		}
		return nil, errors.New("public key is not RSA")
	}

	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}

	return nil, errors.New("unable to parse RSA public key")
}
