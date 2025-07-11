package org.oneedtech.inspect.vc.verification;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.util.SHAUtil;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import io.setl.rdf.normalization.RdfNormalize;

public class URDNA2015Canonicalizer extends Canonicalizer {

    private static final Logger log = LoggerFactory.getLogger(URDNA2015Canonicalizer.class);

    private DataIntegrityProof.Builder<?> proofBuilder;

    // expose intermediate values for reporting
    private DataIntegrityProof ldProofWithoutProofValues;
    private JsonLDObject jsonLdObjectWithoutProof;
    private String canonicalizedLdProofWithoutProofValues;
    private String canonicalizedJsonLdObjectWithoutProof;
    private byte[] canonicalizationResult;

    public URDNA2015Canonicalizer(DataIntegrityProof.Builder<?> proofBuilder) {
        super(List.of("urdna2015"));
        this.proofBuilder = proofBuilder;
    }

    @Override
    public String canonicalize(JsonLDObject jsonLDObject) throws JsonLDException, IOException, NoSuchAlgorithmException {
        RdfDataset rdfDataset = jsonLDObject.toDataset();
        rdfDataset = RdfNormalize.normalize(rdfDataset, "urdna2015");
        StringWriter stringWriter = new StringWriter();
        NQuadsWriter nQuadsWriter = new NQuadsWriter(stringWriter);
        nQuadsWriter.write(rdfDataset);
        return stringWriter.getBuffer().toString();
    }

    @Override
    public byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject) throws IOException, GeneralSecurityException, JsonLDException {

        // construct the LD object without proof
        jsonLdObjectWithoutProof = JsonLDObject.builder()
                .base(jsonLdObject)
                .build();
        DataIntegrityProof.removeFromJsonLdObject(jsonLdObjectWithoutProof);

        // construct the LD proof without proof values
        ldProofWithoutProofValues = proofBuilder
                .base(dataIntegrityProof)
                .defaultContexts(false)
                .build();
        DataIntegrityProof.removeLdProofValues(ldProofWithoutProofValues);

        // canonicalize the LD proof and LD object
        jsonLdObjectWithoutProof.setDocumentLoader(jsonLdObject.getDocumentLoader());
        canonicalizedJsonLdObjectWithoutProof = this.canonicalize(jsonLdObjectWithoutProof);
        byte[] canonicalizedJsonLdObjectWithoutProofHash = SHAUtil.sha256(canonicalizedJsonLdObjectWithoutProof);
        if (log.isDebugEnabled()) log.debug("Canonicalized LD object without proof: {}", canonicalizedJsonLdObjectWithoutProof);
        if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD object without proof: {}", Hex.encodeHexString(canonicalizedJsonLdObjectWithoutProofHash));

        ldProofWithoutProofValues.setDocumentLoader(jsonLdObject.getDocumentLoader());
        canonicalizedLdProofWithoutProofValues = this.canonicalize(ldProofWithoutProofValues);
        byte[] canonicalizedLdProofWithoutProofValuesHash = SHAUtil.sha256(canonicalizedLdProofWithoutProofValues);
        if (log.isDebugEnabled()) log.debug("Canonicalized LD proof without proof value: {}", canonicalizedLdProofWithoutProofValues);
        if (log.isDebugEnabled()) log.debug("Hashed canonicalized LD proof without proof value: {}", Hex.encodeHexString(canonicalizedLdProofWithoutProofValuesHash));

        // construct the canonicalization result

        canonicalizationResult = new byte[64];
        System.arraycopy(canonicalizedLdProofWithoutProofValuesHash, 0, canonicalizationResult, 0, 32);
        System.arraycopy(canonicalizedJsonLdObjectWithoutProofHash, 0, canonicalizationResult, 32, 32);

        return canonicalizationResult;
    }

    public DataIntegrityProof getLdProofWithoutProofValues() {
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