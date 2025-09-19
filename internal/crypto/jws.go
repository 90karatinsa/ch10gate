package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	if err != nil { return JWS{}, err }

	signingInput := protected + "." + pl
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil { return JWS{}, err }

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
