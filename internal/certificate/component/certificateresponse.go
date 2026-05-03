package component

import "time"

type CertifyResponse struct {
	LeafCertificate          []byte
	IntermediateCertificates [][]byte
	NotAfter                 time.Time
}
