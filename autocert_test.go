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

package autocert

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestInitialiseCA_AlreadyInitialised(t *testing.T) {
	defer tearDown()
	caCert = &x509.Certificate{}
	cert, err := InitialiseCA(nil)
	if !errors.Is(ErrCAAlreadyInitialised, err) {
		t.Errorf("Expected CA already intialised error but instead got: %v", err)
	}
	if cert != nil {
		t.Error("InitialiseCA should have returned nil cert")
	}
}

func TestInitialiseCA_NoSubjectName(t *testing.T) {
	defer tearDown()
	cert, err := InitialiseCA(&CertificateOptions{})
	if !errors.Is(err, ErrNameNotProvided) {
		t.Errorf("Expected name not provided error but instead got: %v", err)
	}
	if cert != nil {
		t.Errorf("InitialiseCA should have returned nil cert")
	}
}

func TestInitialiseCA_ExpiryBelowMinimum(t *testing.T) {
	defer tearDown()
	cert, err := InitialiseCA(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().AddDate(4, 0, 0),
	})
	if !errors.Is(err, ErrCAExpiryDateBelowMinimum) {
		t.Errorf("Expected CA expiry date below minimum error but instead got: %v", err)
	}
	if cert != nil {
		t.Errorf("InitialiseCA should have returned nil cert")
	}
}

func TestInitialiseCA_NotPemEncoded(t *testing.T) {
	defer tearDown()
	cert, err := InitialiseCA(&CertificateOptions{
		SubjectName:  "test",
		ExpiryDate:   time.Now().AddDate(5, 0, 0),
		IsPemEncoded: false,
	})
	if err != nil {
		t.Fatalf("Expected no error when initialising CA, instead got: %v", err)
	}

	if cert == nil {
		t.Fatalf("CA certificate was nil")
	}
	p, _ := pem.Decode(cert)
	if p != nil {
		t.Fatalf("Certificate was pem encoded")
	}
}

func TestInitialiseCA_IsPemEncoded(t *testing.T) {
	defer tearDown()
	cert, err := InitialiseCA(&CertificateOptions{
		SubjectName:  "test",
		ExpiryDate:   time.Now().AddDate(5, 0, 0),
		IsPemEncoded: true,
	})
	if err != nil {
		t.Fatalf("Expected no error when initialising CA, instead got: %v", err)
	}

	if cert == nil {
		t.Fatalf("CA certificate was nil")
	}
	p, _ := pem.Decode(cert)
	if p == nil {
		t.Fatalf("Certificate was not pem encoded")
	}
}

func TestInitialiseCA_ValidCA(t *testing.T) {
	defer tearDown()
	expiry := time.Now().AddDate(5, 0, 0)
	certResp, err := InitialiseCA(&CertificateOptions{
		SubjectName: "test",
		Subject: pkix.Name{
			CommonName:   "not-test",
			Country:      []string{"DE"},
			Organization: []string{"FF"},
			Locality:     []string{"local"},
			PostalCode:   []string{"postcode27"},
		},
		ExpiryDate:   expiry,
		IsPemEncoded: true,
	})
	if err != nil {
		t.Fatalf("Expected no error when initialising CA, instead got: %v", err)
	}

	if certResp == nil {
		t.Fatalf("CA certificate was nil")
	}
	p, _ := pem.Decode(certResp)
	if p == nil {
		t.Fatalf("Certificate was not pem encoded")
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("Error when parsing CA certificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("Resulting CA certificate is not marked as a CA certificate")
	}
	if cert.AuthorityKeyId != nil && bytes.Compare(cert.SubjectKeyId, cert.AuthorityKeyId) != 0 {
		t.Error("Resulting CA certificate is not self signed")
	}
	if cert.Subject.CommonName != "test" {
		t.Error("Subject name was not overwritten")
	}
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		t.Error("CA certificate key algorithm was not ed25519")
	}
	if !expiry.Truncate(time.Second).Equal(cert.NotAfter) {
		t.Error("CA certificate expiry time not equal to desired expiry time")
	}
}

func TestInitialiseCA_CADataIsSaved(t *testing.T) {
	defer tearDown()
	expiry := time.Now().AddDate(5, 0, 0)
	certResp, err := InitialiseCA(&CertificateOptions{
		SubjectName: "test",
		Subject: pkix.Name{
			CommonName:   "not-test",
			Country:      []string{"DE"},
			Organization: []string{"FF"},
			Locality:     []string{"local"},
			PostalCode:   []string{"postcode27"},
		},
		ExpiryDate:   expiry,
		IsPemEncoded: true,
	})
	if err != nil {
		t.Fatalf("Expected no error when initialising CA, instead got: %v", err)
	}

	if certResp == nil {
		t.Fatalf("CA certificate was nil")
	}
	if caCert == nil {
		t.Fatalf("CA certificate was not stored in memeory")
	}
	if caKey == nil {
		t.Fatalf("CA private key was not stored in memory")
	}
}

func TestImportCA_CertificateNotPemEncoded(t *testing.T) {
	defer tearDown()

	certData, _, priv := createTestCACertificate(t)
	err := ImportCA(certData, priv)
	if !errors.Is(err, ErrCertificateNotPemEncoded) {
		t.Fatalf("Expected certificate not PEM encoded error when importing CA, instead got: %v", err)
	}
}

func TestImportCA_KeyNotPemEncoded(t *testing.T) {
	defer tearDown()

	certData, _, priv := createTestCACertificate(t)
	out := &bytes.Buffer{}
	err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}

	err = ImportCA(out.Bytes(), priv)
	if !errors.Is(err, ErrKeyNotPemEncoded) {
		t.Fatalf("Expected key not PEM encoded error when importing CA, instead got: %v", err)
	}
}

func TestImportCA_ValidCA(t *testing.T) {
	defer tearDown()

	certData, _, priv := createTestCACertificate(t)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to parse test private key: %v", err)
	}

	cert := &bytes.Buffer{}
	err = pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}
	key := &bytes.Buffer{}
	err = pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}

	err = ImportCA(cert.Bytes(), key.Bytes())
	if err != nil {
		t.Fatalf("Expected no error when importing CA, instead got: %v", err)
	}

	if bytes.Compare(certData, caCert.Raw) != 0 {
		t.Fatalf("Test CA certificate was not the same as resulting CA certificate after import")
	}
	if bytes.Compare(priv, caKey) != 0 {
		t.Fatalf("Test CA key was not the same as resulting CA key after import")
	}
}

func TestImportCA_NotRootCA(t *testing.T) {
	defer tearDown()

	certData, _, priv := createTestCACertificate(t)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to parse test private key: %v", err)
	}

	pemCa, pemCaKey := pemEncodeCertAndKey(t, certData, keyBytes)
	tlsCert, err := tls.X509KeyPair(pemCa, pemCaKey)
	if err != nil {
		t.Fatalf("Failed to test key pair: %v", err)
	}
	rootCACert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse test certificate: %v", err)
	}

	childCert, childPriv := signTestCertificate(t, rootCACert, priv)
	childPrivBytes, err := x509.MarshalPKCS8PrivateKey(childPriv)
	if err != nil {
		t.Fatalf("Failed to parse test private key: %v", err)
	}

	pemChild, pemPriv := pemEncodeCertAndKey(t, childCert, childPrivBytes)
	err = ImportCA(pemChild, pemPriv)
	if !errors.Is(err, ErrCAIsNotRootCA) {
		t.Fatalf("Expected ca is not root CA error when importing CA, instead got: %v", err)
	}
}

func TestRequestCertificate_CANotInitialised(t *testing.T) {
	defer tearDown()

	cert, key, err := RequestCertificate(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().Add(time.Minute * 5),
	})
	if !errors.Is(err, ErrCANotInitialised) {
		t.Fatalf("Expected CA not initialised error, instead got error: %v", err)
	}
	if cert != nil {
		t.Errorf("Expected certificate to be nil")
	}
	if key != nil {
		t.Errorf("Expected key to be nil")
	}
}

func TestRequestCertificate_NoSubjectName(t *testing.T) {
	defer tearDown()
	setupTestCA(t)

	cert, key, err := RequestCertificate(&CertificateOptions{
		ExpiryDate: time.Now().Add(time.Minute * 5),
	})
	if !errors.Is(err, ErrNameNotProvided) {
		t.Fatalf("Expected subject name not provided error, instead got error: %v", err)
	}
	if cert != nil {
		t.Errorf("Expected certificate to be nil")
	}
	if key != nil {
		t.Errorf("Expected key to be nil")
	}
}

func TestRequestCertificate_TtlTooLong(t *testing.T) {
	defer tearDown()
	setupTestCA(t)

	cert, key, err := RequestCertificate(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().Add(time.Minute * 61),
	})
	if !errors.Is(err, ErrCertExpiryExceedsMaximum) {
		t.Fatalf("Expected subject name not provided error, instead got error: %v", err)
	}
	if cert != nil {
		t.Errorf("Expected certificate to be nil")
	}
	if key != nil {
		t.Errorf("Expected key to be nil")
	}
}

func TestRequestCertificate_SignedByCA(t *testing.T) {
	defer tearDown()
	setupTestCA(t)

	certBytes, key, err := RequestCertificate(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().Add(time.Minute * 5),
	})
	if err != nil {
		t.Fatalf("Expected no error, instead got error: %v", err)
	}
	if certBytes == nil {
		t.Errorf("Certificate was nil")
	}
	if key == nil {
		t.Errorf("Key was nil")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}
	if bytes.Compare(cert.AuthorityKeyId, caCert.SubjectKeyId) != 0 {
		t.Errorf("Certificate was not signed by CA")
	}
}

func TestRequestCertificate_KeyMatchesCertificate(t *testing.T) {
	defer tearDown()
	setupTestCA(t)

	certBytes, keyBytes, err := RequestCertificate(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().Add(time.Minute * 5),
	})
	if err != nil {
		t.Fatalf("Expected no error, instead got error: %v", err)
	}
	if certBytes == nil {
		t.Errorf("Certificate was nil")
	}
	if keyBytes == nil {
		t.Errorf("Key was nil")
	}

	certPem, keyPem := pemEncodeCertAndKey(t, certBytes, keyBytes)
	_, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		t.Errorf("Failed to load certificate and key pair: %v", err)
	}
}

func TestRequestCertificate_RunTLSConnection(t *testing.T) {
	defer tearDown()
	setupTestCA(t)

	certBytes, keyBytes, err := RequestCertificate(&CertificateOptions{
		SubjectName: "test",
		ExpiryDate:  time.Now().Add(time.Minute * 5),
		DNSNames:    []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("Expected no error, instead got error: %v", err)
	}
	if certBytes == nil {
		t.Errorf("Certificate was nil")
	}
	if keyBytes == nil {
		t.Errorf("Key was nil")
	}

	certFile, err := os.Create("cert.crt")
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer certFile.Close()
	certKeyFile, err := os.Create("cert-key.crt")
	if err != nil {
		t.Fatalf("Failed to create certificate key file: %v", err)
	}
	defer certKeyFile.Close()

	err = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}
	err = pem.Encode(certKeyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}

	http.HandleFunc("/test", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Content-Type", "text/plain")
		writer.Write([]byte("test complete"))
	})
	go func() {
		err = http.ListenAndServeTLS("localhost:8089", certFile.Name(), certKeyFile.Name(), nil)
		if err != nil {
			t.Errorf("Failed to start tls server: %v", err)
		}
	}()

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	conf := &tls.Config{
		RootCAs: roots,
	}
	conn, err := tls.Dial("tcp", "localhost:8089", conf)
	if err != nil {
		t.Fatalf("Failed to connect via tls: %v", err)
	}
	defer conn.Close()
	os.Remove(certFile.Name())
	os.Remove(certKeyFile.Name())
}

func BenchmarkRequestCertificate(b *testing.B) {
	defer tearDown()

	_, err := InitialiseCA(&CertificateOptions{
		SubjectName: "test-ca",
		ExpiryDate:  time.Now().AddDate(5, 0, 0),
	})
	if err != nil {
		b.Fatalf("Failed to initialise CA: %v", err)
	}
	for i := 0; i < b.N; i++ {
		_, _, err := RequestCertificate(&CertificateOptions{
			SubjectName:  "child-" + strconv.Itoa(i),
			ExpiryDate:   time.Now().Add(time.Minute * 5),
			IsPemEncoded: true,
		})
		if err != nil {
			b.Fatalf("Error requesting certificate: %v", err)
		}
	}
}

func pemEncodeCertAndKey(t *testing.T, certData []byte, keyData []byte) ([]byte, []byte) {
	cert := &bytes.Buffer{}
	err := pem.Encode(cert, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}
	key := &bytes.Buffer{}
	err = pem.Encode(key, &pem.Block{Type: "PRIVATE KEY", Bytes: keyData})
	if err != nil {
		t.Fatalf("Failed to PEM encode test certificate: %v", err)
	}
	return cert.Bytes(), key.Bytes()
}

func setupTestCA(t *testing.T) {
	_, err := InitialiseCA(&CertificateOptions{
		SubjectName: "test-ca",
		ExpiryDate:  time.Now().AddDate(5, 0, 0),
	})
	if err != nil {
		t.Fatalf("Failed to setup test CA: %v", err)
	}
}

func signTestCertificate(t *testing.T, parent *x509.Certificate, parentPriv crypto.PrivateKey) ([]byte, ed25519.PrivateKey) {
	certTemp := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject:      pkix.Name{CommonName: "signed-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Minute * 5),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	pub, priv, err := generateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create key pair for test certificate: %v", err)
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemp, parent, pub, parentPriv)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}
	return certBytes, priv
}

func createTestCACertificate(t *testing.T) ([]byte, ed25519.PublicKey, ed25519.PrivateKey) {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(serialNumber),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	pub, priv, err := generateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to create key pair for testing: %v", err)
	}
	certData, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}
	return certData, pub, priv
}

func tearDown() {
	caCert = nil
	caKey = nil
	serialNumber = 1234
}
