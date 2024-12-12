package org.oneedtech.inspect.vc.verification;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.util.SHAUtil;

public class URDNA2015Canonicalizer extends Canonicalizer {

    private LdProof.Builder<?> proofBuilder;

    // expose intermediate values for reporting
    private LdProof ldProofWithoutProofValues;
    private JsonLDObject jsonLdObjectWithoutProof;
    private String canonicalizedLdProofWithoutProofValues;
    private String canonicalizedJsonLdObjectWithoutProof;
    private byte[] canonicalizationResult;

    public URDNA2015Canonicalizer(LdProof.Builder<?> proofBuilder) {
        super(List.of("urdna2015"));
        this.proofBuilder = proofBuilder;
    }

    @Override
    public byte[] canonicalize(LdProof ldProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD proof without proof values
        ldProofWithoutProofValues = proofBuilder
                .base(ldProof)
                .defaultContexts(true)
                .build();
        LdProof.removeLdProofValues(ldProofWithoutProofValues);

        // construct the LD object without proof

        jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        LdProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // canonicalize the LD proof and LD object

        canonicalizedLdProofWithoutProofValues = ldProofWithoutProofValues.normalize("urdna2015");
        canonicalizedJsonLdObjectWithoutProof = jsonLdObjectWithoutProof.normalize("urdna2015");

        // construct the canonicalization result

        canonicalizationResult = new byte[64];
        System.arraycopy(SHAUtil.sha256(canonicalizedLdProofWithoutProofValues), 0, canonicalizationResult, 0, 32);
        System.arraycopy(SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof), 0, canonicalizationResult, 32, 32);

        return canonicalizationResult;
    }

    public LdProof getLdProofWithoutProofValues() {
        return ldProofWithoutProofValues;
    }

    public JsonLDObject getJsonLdObjectWithoutProof() {
        return jsonLdObjectWithoutProof;
    }

    public String getCanonicalizedLdProofWithoutProofValues() {
        return canonicalizedLdProofWithoutProofValues;
    }

    public String getCanonicalizedJsonLdObjectWithoutProof() {
        return canonicalizedJsonLdObjectWithoutProof;
    }

    public byte[] getCanonicalizationResult() {
        return canonicalizationResult;
    }
}