package vc

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignatureproof2020"

	verifiable2 "github.com/hyperledger/aries-framework-go/pkg/controller/command/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/bbsblssignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/stretchr/testify/require"
)

const vcForDerive = `
	{
	 	"@context": [
	   		"https://www.w3.org/2018/credentials/v1",
	   		"https://w3id.org/citizenship/v1",
	   		"https://w3id.org/security/bbs/v1"
	 	],
	 	"id": "https://issuer.oidp.uscis.gov/credentials/83627465",
	 	"type": [
	   		"VerifiableCredential",
	   		"PermanentResidentCard"
	 	],
	 	"issuer": "did:example:489398593",
	 	"identifier": "83627465",
	 	"name": "Permanent Resident Card",
	 	"description": "Government of Example Permanent Resident Card.",
	 	"issuanceDate": "2019-12-03T12:19:52Z",
	 	"expirationDate": "2029-12-03T12:19:52Z",
	 	"credentialSubject": {
	   		"id": "did:example:b34ca6cd37bbf23",
	   		"type": [
	     		"PermanentResident",
	     		"Person"
	   		],
	   		"givenName": "JOHN",
	   		"familyName": "SMITH",
	   		"gender": "Male",
	   		"image": "data:image/png;base64,iVBORw0KGgokJggg==",
	   		"residentSince": "2015-01-01",
	   		"lprCategory": "C09",
	   		"lprNumber": "999-999-999",
	   		"commuterClassification": "C1",
	   		"birthCountry": "Bahamas",
	   		"birthDate": "1958-07-17"
	 	}
	}
`

func TestFoo(t *testing.T) {
	//////////////////////////////////////////////////////////////////////////////////
	// Sign on VC
	//////////////////////////////////////////////////////////////////////////////////

	vc, err := verifiable.ParseCredential([]byte(vcForDerive))
	require.NoError(t, err)

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	_, keyID := fingerprint.CreateDIDKeyByCode(fingerprint.BLS12381g2PubKeyMultiCodec, pubKeyBytes)
	keyID = "did:panacea:21234#key1"

	bbsSigner, err := newBBSSigner(privKey)
	require.NoError(t, err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()),
	)

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           verifiable2.BbsBlsSignature2020,
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	err = vc.AddLinkedDataProof(ldpContext)
	require.NoError(t, err)

	b, err := json.MarshalIndent(vc, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))

	vcSignedBytes, err := json.Marshal(vc)
	require.NoError(t, err)

	//////////////////////////////////////////////////////////////////////////////////
	// Verify VC
	//////////////////////////////////////////////////////////////////////////////////

	//anotherPubKey, _, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	//require.NoError(t, err)
	//anotherPubKeyBytes, err := anotherPubKey.Marshal()
	//require.NoError(t, err)

	vcVerified, err := verifiable.ParseCredential(
		vcSignedBytes,
		verifiable.WithEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)
	require.NoError(t, err)

	b, err = json.MarshalIndent(vcVerified, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))

	//////////////////////////////////////////////////////////////////////////////////
	// Create VP
	//////////////////////////////////////////////////////////////////////////////////

	testVp(t, vc)

	testVpSelectiveDisclosure(t, vc, pubKeyBytes)
}

func testVp(t *testing.T, vc *verifiable.Credential) {
	did := "did:panacea:22222222222222222"
	keyID := fmt.Sprintf("%s#key1", did)

	bbsLoader, err := bbsJSONLDDocumentLoader()
	require.NoError(t, err)

	pubKey, privKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	bbsSigner, err := newBBSSigner(privKey)
	require.NoError(t, err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()),
	)

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           verifiable2.BbsBlsSignature2020,
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(vc))
	require.NoError(t, err)

	vp.Context = append(vp.Context, bbsContext)
	vp.Holder = did

	err = vp.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(bbsLoader))
	require.NoError(t, err)

	b, err := json.MarshalIndent(vp, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))

	vpSignedBytes, err := vp.MarshalJSON()
	require.NoError(t, err)

	/////////////// Verify VP

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)

	vpVerified, err := verifiable.ParsePresentation(
		vpSignedBytes,
		verifiable.WithPresEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(pubKeyBytes, "Bls12381G2Key2020")),
	)
	require.NoError(t, err)

	b, err = json.MarshalIndent(vpVerified, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))
}

const revealDocJSON = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/citizenship/v1",
    "https://w3id.org/security/bbs/v1"
  ],
  "type": ["VerifiableCredential", "PermanentResidentCard"],
  "credentialSubject": {
    "@explicit": true,
    "type": ["PermanentResident", "Person"],
    "givenName": {},
    "familyName": {},
    "gender": {}
  }
}
`

func testVpSelectiveDisclosure(t *testing.T, vc *verifiable.Credential, issuerPubKeyBytes []byte) {
	////////////////////////////
	/// VC Selective Disclosure
	////////////////////////////
	revealDoc, err := toMap(revealDocJSON)
	require.NoError(t, err)

	nonce := []byte("this is a nonce")
	revealVC, err := vc.GenerateBBSSelectiveDisclosure(
		revealDoc,
		nonce,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(issuerPubKeyBytes, "Bls12381G2Key2020")),
	)
	require.NoError(t, err)

	b, err := json.MarshalIndent(revealVC, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))

	////////////////////////////
	/// VC -> VP
	////////////////////////////
	did := "did:panacea:33333333333333333"
	keyID := fmt.Sprintf("%s#key1", did)

	bbsLoader, err := bbsJSONLDDocumentLoader()
	require.NoError(t, err)

	holderPubKey, holderPrivKey, err := bbs12381g2pub.GenerateKeyPair(sha256.New, nil)
	require.NoError(t, err)

	bbsSigner, err := newBBSSigner(holderPrivKey)
	require.NoError(t, err)

	sigSuite := bbsblssignature2020.New(
		suite.WithSigner(bbsSigner),
		suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()),
	)

	ldpContext := &verifiable.LinkedDataProofContext{
		SignatureType:           verifiable2.BbsBlsSignature2020,
		SignatureRepresentation: verifiable.SignatureProofValue,
		Suite:                   sigSuite,
		VerificationMethod:      keyID,
	}

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(revealVC))
	require.NoError(t, err)

	vp.Context = append(vp.Context, bbsContext)
	vp.Holder = did

	err = vp.AddLinkedDataProof(ldpContext, jsonld.WithDocumentLoader(bbsLoader))
	require.NoError(t, err)

	b, err = json.MarshalIndent(vp, "", "  ")
	require.NoError(t, err)
	fmt.Println(string(b))

	vpSignedBytes, err := vp.MarshalJSON()
	require.NoError(t, err)

	////////////////////////////
	/// Verify VP and all VCs
	////////////////////////////

	holderPubKeyBytes, err := holderPubKey.Marshal()
	require.NoError(t, err)

	vpVerified, err := verifiable.ParsePresentation(
		vpSignedBytes,
		verifiable.WithPresEmbeddedSignatureSuites(sigSuite),
		verifiable.WithPresPublicKeyFetcher(verifiable.SingleKey(holderPubKeyBytes, "Bls12381G2Key2020")),
	)
	require.NoError(t, err)

	marshalledVCs, err := vpVerified.MarshalledCredentials()
	require.NoError(t, err)

	for _, vcBytes := range marshalledVCs {
		_, err = verifiable.ParseCredential(
			vcBytes,
			verifiable.WithEmbeddedSignatureSuites(
				bbsblssignature2020.New(
					suite.WithVerifier(bbsblssignature2020.NewG2PublicKeyVerifier()),
				),
				bbsblssignatureproof2020.New(
					suite.WithVerifier(bbsblssignatureproof2020.NewG2PublicKeyVerifier(nonce)),
				),
			),
			verifiable.WithPublicKeyFetcher(verifiable.SingleKey(issuerPubKeyBytes, "Bls12381G2Key2020")),
		)
		require.NoError(t, err)
	}
}

func toMap(v interface{}) (map[string]interface{}, error) {
	var (
		b   []byte
		err error
	)

	switch cv := v.(type) {
	case []byte:
		b = cv
	case string:
		b = []byte(cv)
	default:
		b, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	var m map[string]interface{}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
