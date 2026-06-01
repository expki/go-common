package x509

import "encoding/asn1"

// Extension OID constants for the RFC 5280 §4.2 standard certificate and CSR
// extensions. Two arcs are used:
//
//   - id-ce  = { joint-iso-ccitt(2) ds(5) certificateExtension(29) }  (RFC 5280 §4.2.1, rfc5280.txt:1485+)
//   - id-pe  = { iso(1) identified-organization(3) dod(6) internet(1)
//     security(5) mechanisms(5) pkix(7) 1 }                 (private extensions, AIA/SIA)
//
// All identifiers are exported as asn1.ObjectIdentifier values. They are the
// single source of truth that extensions.go, san.go, and builder.go dispatch
// on; do not redeclare these elsewhere.
var (
	// id-ce arc: { 2 5 29 }
	oidExtensionSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14} // id-ce 14
	oidExtensionKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15} // id-ce 15
	oidExtensionSubjectDirectoryAttrs  = asn1.ObjectIdentifier{2, 5, 29, 9}  // id-ce 9
	oidExtensionSubjectAltName         = asn1.ObjectIdentifier{2, 5, 29, 17} // id-ce 17
	oidExtensionIssuerAltName          = asn1.ObjectIdentifier{2, 5, 29, 18} // id-ce 18
	oidExtensionBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19} // id-ce 19
	oidExtensionNameConstraints        = asn1.ObjectIdentifier{2, 5, 29, 30} // id-ce 30
	oidExtensionCRLDistributionPoints  = asn1.ObjectIdentifier{2, 5, 29, 31} // id-ce 31
	oidExtensionCertificatePolicies    = asn1.ObjectIdentifier{2, 5, 29, 32} // id-ce 32
	oidExtensionPolicyMappings         = asn1.ObjectIdentifier{2, 5, 29, 33} // id-ce 33
	oidExtensionAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35} // id-ce 35
	oidExtensionPolicyConstraints      = asn1.ObjectIdentifier{2, 5, 29, 36} // id-ce 36
	oidExtensionExtendedKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37} // id-ce 37
	oidExtensionFreshestCRL            = asn1.ObjectIdentifier{2, 5, 29, 46} // id-ce 46
	oidExtensionInhibitAnyPolicy       = asn1.ObjectIdentifier{2, 5, 29, 54} // id-ce 54

	// id-pe arc: { 1 3 6 1 5 5 7 1 }
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}  // id-pe 1
	oidExtensionSubjectInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11} // id-pe 11
)
