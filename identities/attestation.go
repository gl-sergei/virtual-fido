package identities

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/bulwarkid/virtual-fido/cose"
)

func CreateSelfSignedAttestationCertificate(
	certificateAuthority *x509.Certificate,
	certificateAuthorityPrivateKey *ecdsa.PrivateKey,
	targetPrivateKey *cose.SupportedCOSEPrivateKey) (*x509.Certificate, error) {
	// TODO: Fill in fields like SerialNumber and SubjectKeyIdentifier
	templateCert := &x509.Certificate{
		Version:      2,
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization:       []string{"Self-Signed Virtual FIDO"},
			Country:            []string{"US"},
			CommonName:         "Self-Signed Virtual FIDO",
			OrganizationalUnit: []string{"Authenticator Attestation"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		templateCert,
		certificateAuthority,
		targetPrivateKey.Public().Any(),
		certificateAuthorityPrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}

func CreateCAPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func CreateSelfSignedCA(privateKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	authority := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			Organization: []string{"Self-Signed Virtual FIDO"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, authority, authority, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
}
