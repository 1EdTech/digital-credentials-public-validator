package org.oneedtech.inspect.vc.probe;

import java.util.HexFormat;

import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

public class EmbeddedProofModel extends GeneratedObject {
	public static final String ID = "vc.embedded.proof";


    private final String ldProofWithoutProofValues;
    private final String jsonLdObjectWithoutProof;
    private final String canonicalizedLdProofWithoutProofValues;
    private final String canonicalizedJsonLdObjectWithoutProof;
    private final String canonicalizationResult;

    public EmbeddedProofModel(URDNA2015Canonicalizer canonicalizer) {
        super(ID, Type.INTERNAL);
        this.ldProofWithoutProofValues = canonicalizer.getLdProofWithoutProofValues().toJson(true);
        this.jsonLdObjectWithoutProof = canonicalizer.getJsonLdObjectWithoutProof().toJson(true);
        this.canonicalizedLdProofWithoutProofValues = canonicalizer.getCanonicalizedLdProofWithoutProofValues();
        this.canonicalizedJsonLdObjectWithoutProof = canonicalizer.getCanonicalizedJsonLdObjectWithoutProof();
        this.canonicalizationResult = HexFormat.of().formatHex(canonicalizer.getCanonicalizationResult());
    }

    public String getLdProofWithoutProofValues() {
        return ldProofWithoutProofValues;
    }

    public String getJsonLdObjectWithoutProof() {
        return jsonLdObjectWithoutProof;
    }

    public String getCanonicalizedLdProofWithoutProofValues() {
        return canonicalizedLdProofWithoutProofValues;
    }

    public String getCanonicalizedJsonLdObjectWithoutProof() {
        return canonicalizedJsonLdObjectWithoutProof;
    }

    public String getCanonicalizationResult() {
        return canonicalizationResult;
    }
}
