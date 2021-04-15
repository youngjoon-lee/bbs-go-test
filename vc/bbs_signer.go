package vc

import (
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/presexch"
	"github.com/piprate/json-gold/ld"
	"strings"
)

type bbsSigner struct {
	privKeyBytes []byte
}

func newBBSSigner(privKey *bbs12381g2pub.PrivateKey) (*bbsSigner, error) {
	privKeyBytes, err := privKey.Marshal()
	if err != nil {
		return nil, err
	}

	return &bbsSigner{privKeyBytes: privKeyBytes}, nil
}

func (s *bbsSigner) Sign(data []byte) ([]byte, error) {
	msgs := s.textToLines(string(data))

	return bbs12381g2pub.New().Sign(msgs, s.privKeyBytes)
}

func (s *bbsSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

const bbsContext = "https://w3id.org/security/bbs/v1"

// TODO: context should not be loaded here, the loader should be defined once for the whole system.
func bbsJSONLDDocumentLoader() (*ld.CachingDocumentLoader, error) {
	loader := presexch.CachingJSONLDLoader()

	reader, err := ld.DocumentFromReader(strings.NewReader(contextBBSContent))
	if err != nil {
		return nil, err
	}

	loader.AddDocument(bbsContext, reader)

	return loader, nil
}

const contextBBSContent = `{
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "ldssk": "https://w3id.org/security#",
    "BbsBlsSignature2020": {
      "@id": "https://w3id.org/security#BbsBlsSignature2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "proofValue": "sec:proofValue",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "BbsBlsSignatureProof2020": {
      "@id": "https://w3id.org/security#BbsBlsSignatureProof2020",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "sec": "https://w3id.org/security#",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "challenge": "sec:challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "xsd:dateTime"
        },
        "domain": "sec:domain",
        "nonce": "sec:nonce",
        "proofPurpose": {
          "@id": "sec:proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "sec": "https://w3id.org/security#",
            "assertionMethod": {
              "@id": "sec:assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "sec:authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "proofValue": "sec:proofValue",
        "verificationMethod": {
          "@id": "sec:verificationMethod",
          "@type": "@id"
        }
      }
    },
    "Bls12381G2Key2020": "ldssk:Bls12381G2Key2020"
  }
}`

