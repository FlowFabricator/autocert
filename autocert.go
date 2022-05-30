/*
 * GNU Lesser General Public License
 * Copyright (C) 2022 Spica Innovations S.R.L
 * alex@flowfabricator.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/*
Package autocert is an opinionated pki library for non-production use. This library can be used to set up a CA and sign
certificates. There can only be 1 CA, and it must use a long-lived certificate (5+ years). All certificates use
ed25519 public keys. CAs can be imported however they must be a root CA certificate.
*/
package autocert

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

/*
CertificateOptions Configuration options for a certificate
*/
type CertificateOptions struct {
	// SubjectName Required field. Overrides Subject.CommonName.
	// If nil, ErrNameNotProvided is returned
	SubjectName string

	// Subject Optional details field for the certificate subject.
	// SubjectName will override the Subject.CommonName field
	Subject pkix.Name

	// ExpiryDate The time this certificate will expire.
	// CA certificates must be at least five years from now or ErrCAExpiryDateBelowMinimum will be returned.
	// Other certificates must be less than an hour from now or ErrCertExpiryExceedsMaximum will be returned.
	ExpiryDate time.Time

	// IsPemEncoded Dictates whether returned certificates are PEM encoded or not.
	// CA certificates are available both PEM encoded and non-PEM encoded,
	// when creating CA certificates, this option will only determine which is returned.
	IsPemEncoded bool

	// DNSNames DNS names which this certificate is valid for.
	DNSNames []string

	// IPAddresses IP addresses which this certificate is valid for.
	IPAddresses []net.IP

	// URIs URLs which this certificate is valid for.
	URIs []*url.URL
}

var (
	// caCert Currently configured CA certificate.
	caCert *x509.Certificate

	// caKey Public key pair for the current CA.
	caKey ed25519.PrivateKey

	// caCertPem PEM encoded byte array of the current CA certificate.
	caCertPem []byte

	// caKeyPem PEM encoded byte array of the current CA private key.
	caKeyPem []byte

	// serialNumber The current serial number. Gets incremented with every certificate which is created
	serialNumber int64 = 1234

	// ErrCAAlreadyInitialised Returned when a CA initialisation request is made while there is already a CA
	ErrCAAlreadyInitialised = errors.New("CA is already initialised")

	// ErrCANotInitialised Returned when a certificate is requested but no CA is initialised
	ErrCANotInitialised = errors.New("CA has not been initialised")

	// ErrCAIsNotRootCA Returned when a CA is imported which is an intermediate CA certificate
	ErrCAIsNotRootCA = errors.New("CA must be a root CA")

	// ErrCertificateNotPemEncoded Returned when a CA is imported but the CA certificate is not PEM encoded
	ErrCertificateNotPemEncoded = errors.New("provided certificate was not PEM encoded")

	// ErrKeyNotPemEncoded Returned when a CA is imported but the CA private key is not PEM encoded
	ErrKeyNotPemEncoded = errors.New("provided key was not PEM encoded")

	// ErrNameNotProvided Returned when a certificate is requested but no SubjectName or Subject.CommonName is given
	ErrNameNotProvided = errors.New("certificate subject name not provided")

	// ErrCAExpiryDateBelowMinimum Returned when a CA is initialised with an expiry date less than 5 years from now
	ErrCAExpiryDateBelowMinimum = errors.New("CA certificate expiry date must be minimum of 5 years from now")

	// ErrCertExpiryExceedsMaximum Returned when a certificate is requested but the expiry date is greater than 1 hour from now
	ErrCertExpiryExceedsMaximum = errors.New("certificate expiry date exceeds maximum value of 1 hour from now")
)

/*
InitialiseCA Creates a root CA and sets it as the current CA. Returns the CA certificate as raw bytes.
If certOpts.IsPemEncoded is true, returns raw bytes PEM encoded
*/
func InitialiseCA(certOpts *CertificateOptions) ([]byte, error) {
	// Get the time the request was made
	now := time.Now().Add(time.Minute * -1)

	// If a CA is already setup, return ErrCAAlreadyInitialised
	if caCert != nil {
		return nil, ErrCAAlreadyInitialised
	}

	// Overwrite the subject.CommonName with SubjectName
	if certOpts.SubjectName != "" {
		certOpts.Subject.CommonName = certOpts.SubjectName
	} else if certOpts.Subject.CommonName == "" {
		return nil, ErrNameNotProvided
	}
	// Set default expiry if none set and check expiry date after 5 years
	if certOpts.ExpiryDate.IsZero() {
		certOpts.ExpiryDate = now.AddDate(10, 0, 0)
	}
	if certOpts.ExpiryDate.Before(now.AddDate(5, 0, 0)) {
		return nil, ErrCAExpiryDateBelowMinimum
	}

	// Create CA certificate template
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               certOpts.Subject,
		NotBefore:             now,
		NotAfter:              certOpts.ExpiryDate,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	serialNumber++

	// Create key pair
	pub, priv, err := generateEd25519KeyPair()
	if err != nil {
		return nil, err
	}
	// Create the actual self-signed certificate using the template and key pair
	certData, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return nil, err
	}
	// Parse certificate data into x509.Certificate
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return nil, err
	}
	// Convert private key to PKCS8 ASN1 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	// PEM encode certificate and key
	certWriter := &bytes.Buffer{}
	err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		return nil, err
	}
	keyWriter := &bytes.Buffer{}
	err = pem.Encode(keyWriter, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		return nil, err
	}

	// Set the values as the current CA values
	caCertPem = certWriter.Bytes()
	caKeyPem = keyWriter.Bytes()
	caCert = cert
	caKey = priv

	if certOpts.IsPemEncoded {
		return caCertPem, nil
	}
	return certData, nil
}

/*
ImportCA Parses a PEM encoded certificate and key, and sets it as the current CA.
Must be a root CA certificate, intermediate CAs will return ErrCAIsNotRootCA
*/
func ImportCA(certificate []byte, key []byte) error {
	// If CA is already initialised, return ErrCAAlreadyInitialised
	if caCert != nil {
		return ErrCAAlreadyInitialised
	}
	cert, tlsCert, err := ParseRootCA(certificate, key)
	if err != nil {
		return err
	}

	// Set the values as the current CA
	caCertPem = certificate
	caKeyPem = key
	caKey = tlsCert.PrivateKey.(ed25519.PrivateKey)
	caCert = cert
	return nil
}

func ParseRootCA(certificate []byte, key []byte) (*x509.Certificate, tls.Certificate, error) {
	// Check if certificate and key is PEM encoded
	if p, _ := pem.Decode(certificate); p == nil {
		return nil, tls.Certificate{}, ErrCertificateNotPemEncoded
	}
	if p, _ := pem.Decode(key); p == nil {
		return nil, tls.Certificate{}, ErrKeyNotPemEncoded
	}
	// Load the certificate and key pair
	tlsCert, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	// Parse into x509.Certificate object
	cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	// Check the certificate is a root CA, if not, return ErrCAIsNotRootCA
	if cert.AuthorityKeyId != nil && bytes.Compare(cert.AuthorityKeyId, cert.SubjectKeyId) != 0 {
		return nil, tls.Certificate{}, ErrCAIsNotRootCA
	}
	return cert, tlsCert, nil
}

/*
RequestCertificate Returns a certificate signed by the current CA. Requires a CA to already be initialised.
Returns the certificate and private key as raw bytes. If certOpts.IsPemEncoded is true, returns the certificate and key
as PEM encoded byte arrays.
*/
func RequestCertificate(certOpts *CertificateOptions) ([]byte, []byte, error) {
	// Get time of request
	now := time.Now()

	// If CA is not initialised, return ErrCANotInitialised
	if caCert == nil || caKey == nil {
		return nil, nil, ErrCANotInitialised
	}
	// Set the subject.CommonName as certOpts.SubjectName
	if certOpts.SubjectName != "" {
		certOpts.Subject.CommonName = certOpts.SubjectName
	} else if certOpts.Subject.CommonName == "" {
		return nil, nil, ErrNameNotProvided
	}
	// Set default expiry time and check expiry time is within constraints
	if certOpts.ExpiryDate.IsZero() {
		certOpts.ExpiryDate = now.Add(time.Minute * 15)
	}
	if now.Add(time.Hour).Before(certOpts.ExpiryDate) {
		return nil, nil, ErrCertExpiryExceedsMaximum
	}

	// Create certificate template
	certTemp := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject:      certOpts.Subject,
		NotBefore:    now,
		NotAfter:     certOpts.ExpiryDate,
		DNSNames:     certOpts.DNSNames,
		IPAddresses:  certOpts.IPAddresses,
		URIs:         certOpts.URIs,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	serialNumber++

	// Create key pair for this certificate
	pub, priv, err := generateEd25519KeyPair()
	if err != nil {
		return nil, nil, err
	}
	// Create the actual certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemp, caCert, pub, caKey)
	if err != nil {
		return nil, nil, err
	}
	// Convert private key to PKCS8 ASN1 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	// If certOpts.IsPemEncoded is true, return certificate and key as PEM encoded byte arrays
	if certOpts.IsPemEncoded {
		// PEM encode certificate
		certWriter := &strings.Builder{}
		err = pem.Encode(certWriter, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		if err != nil {
			return nil, nil, err
		}

		// PEM encode key
		keyWriter := &strings.Builder{}
		err = pem.Encode(keyWriter, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		if err != nil {
			return nil, nil, err
		}
		return []byte(certWriter.String()), []byte(keyWriter.String()), nil
	}
	return certBytes, keyBytes, nil
}

/*
ClearCA removes any stored CA data. In order to issue certificates, InitialiseCA or
ImportCA will have to be called again.
*/
func ClearCA() {
	caCertPem = nil
	caKeyPem = nil
	caCert = nil
	caKey = nil
}

/*
GetCACertificate Returns the current CA certificate
*/
func GetCACertificate() *x509.Certificate {
	return caCert
}

/*
GetPemEncodedCACertificate Returns current CA certificate, PEM encoded
*/
func GetPemEncodedCACertificate() []byte {
	return caCertPem
}

/*
GetCAKey Return current CA private key. If pemEncoded is true, return PEM encoded key, otherwise return non
pem encoded key
*/
func GetCAKey(pemEncoded bool) []byte {
	if pemEncoded {
		return caKeyPem
	}
	return caKey
}

/*
generateEd25519KeyPair Create an ED25519 public key pair
*/
func generateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
