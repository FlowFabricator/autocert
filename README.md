# Autocert

## Usage

Import the library with 
``` go
import "github.com/FlowFabricator/autocert"
```

To issue certificates, first create a CA
``` go
caCertsOpts := autocert.&CertificateOptions{
	SubjectName: "test-ca",
}
rootCA, err := autocert.InitialiseCA(caCertsOpts)
```

Or import an existing CA using a PEM encoded certificate and private key. Note: when importing an existing CA, it must be a root CA. Importing intermediate CAs will return an error
``` go
caCert, caKey := getExistingCA()
err := autocert.ImportCA(caCert, caKey)
```

To issue certificates signed by this CA:
``` go
certsOpts := &autocert.CertificateOptions{
	SubjectName: "test1",
	IsPemEncoded: true,
	DNSNames: []string{"localhost", "mydomain"},
	IPAddresses: []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::"),
		net.ParseIP("192.32.471.2"),
	},
}
pemEncCert, pemEncKey, err := autocert.RequestCertificate(certsOpts)
```

CA certificates have a minimum time to live of 5 years, attempting to make a CA with a shorter time to live will result in an error. Certificates signed by the CA have a maximum time to live of 1 hour, attempting to create longer lived certificates will result in an error.

Certificate time to live is set in CertificateOptions as follows:
``` go
caOpts := &autocert.CertificateOptions{
    SubjectName: "test1", 
    ExpiryDate:  time.Now().AddDate(10, 0, 0), /* 10 years from now */
}
// Or
certOpts := &autocert.CertificateOptions{
    SubjectName: "test1", 
    ExpiryDate:  time.Now().Add(time.Minute * 10), /* 10 minutes from now */
}
```

All CA certificates are saved both PEM encoded and non PEM encoded, the CertificateOptions parameter ```IsPemEncoded``` has no effect in CA certificates.

When getting a CA certificate or key, you can get either version as follows:
``` go
// Get non PEM encoded
rootCa := autocert.GetCACertificate() /* Returns *x509.Certificate */
rootCaKey := autocert.GetCAKey(false)

// Get PEM encoded
rootCa := autocert.GetPemEncodedCACertificate() /* Returns byte array */
rootCaKey := autocert.GetCAKey(true)
```