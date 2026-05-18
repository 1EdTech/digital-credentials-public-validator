package org.oneedtech.inspect.vc.verification;

import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.RdfResource;
import com.apicatalog.rdf.api.RdfConsumerException;
import com.apicatalog.rdf.canon.RdfCanon;
import com.apicatalog.rdf.lang.RdfConstants;
import com.apicatalog.rdf.nquads.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * RDFC 1.0 canonicalizer for use with ECDSA-SD 2023.
 * The ecdsa-sd-2023 cryptosuite requires RDFC 1.0 (W3C RDF Dataset Canonicalization),
 * which uses SHA-256 internally — unlike the SHA-384 variant of URDNA2015 that was
 * previously used for P-384 keys.
 */
public class RDFC10Canonicalizer extends Canonicalizer {

    public RDFC10Canonicalizer() {
        super(List.of("rdfc-1.0"));
    }

    @Override
    public String canonicalize(JsonLDObject jsonLDObject)
        throws JsonLDException, IOException, NoSuchAlgorithmException {
        RdfDataset rdfDataset = jsonLDObject.toDataset();
        RdfCanon rdfCanon = RdfCanon.create("SHA-256");
        feedDataset(rdfDataset, rdfCanon);

        StringWriter stringWriter = new StringWriter();
        NQuadsWriter nQuadsWriter = new NQuadsWriter(stringWriter);
        try {
            rdfCanon.provide(nQuadsWriter);
        } catch (RdfConsumerException e) {
            throw new IOException("RDFC 1.0 canonicalization failed", e);
        }
        return stringWriter.toString();
    }

    @Override
    public byte[] canonicalize(DataIntegrityProof dataIntegrityProof, JsonLDObject jsonLdObject)
        throws IOException, GeneralSecurityException, JsonLDException {
        throw new UnsupportedOperationException(
            "Full canonicalization not applicable for ECDSA-SD 2023 RDFC 1.0 canonicalizer");
    }

    /**
     * Feeds all quads from a (titanium-json-ld 1.x) RdfDataset into an RdfCanon consumer.
     * Bridges the old com.apicatalog.rdf.RdfDataset API to the new RdfQuadConsumer API.
     */
    static void feedDataset(RdfDataset dataset, RdfCanon rdfCanon) {
        for (RdfNQuad nquad : dataset.toList()) {
            feedNQuad(nquad, rdfCanon);
        }
    }

    private static void feedNQuad(RdfNQuad nquad, RdfCanon rdfCanon) {
        String graph = nquad.getGraphName().map(RdfResource::getValue).orElse(null);
        if (nquad.getObject().isLiteral()) {
            if (nquad.getObject().asLiteral().getLanguage().isPresent()) {
                rdfCanon.quad(
                    nquad.getSubject().getValue(),
                    nquad.getPredicate().getValue(),
                    nquad.getObject().getValue(),
                    nquad.getObject().asLiteral().getDatatype(),
                    nquad.getObject().asLiteral().getLanguage().get(),
                    null,
                    graph);
                return;
            }
            String datatype = nquad.getObject().asLiteral().getDatatype();
            if (datatype.startsWith(RdfConstants.I18N_BASE)) {
                String[] langDir = datatype.substring(RdfConstants.I18N_BASE.length()).split("_");
                rdfCanon.quad(
                    nquad.getSubject().getValue(),
                    nquad.getPredicate().getValue(),
                    nquad.getObject().getValue(),
                    RdfConstants.I18N_BASE,
                    langDir[0],
                    langDir.length > 1 ? langDir[1] : null,
                    graph);
                return;
            }
            rdfCanon.quad(
                nquad.getSubject().getValue(),
                nquad.getPredicate().getValue(),
                nquad.getObject().getValue(),
                datatype, null, null, graph);
            return;
        }
        rdfCanon.quad(
            nquad.getSubject().getValue(),
            nquad.getPredicate().getValue(),
            nquad.getObject().getValue(),
            null, null, null, graph);
    }
}
