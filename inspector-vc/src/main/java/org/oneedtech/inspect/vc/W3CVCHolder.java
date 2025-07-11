package org.oneedtech.inspect.vc;

import java.io.StringReader;
import java.net.URI;
import java.util.List;
import java.util.Map;

import org.oneedtech.inspect.vc.jsonld.JsonLDObjectUtils;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.danubetech.dataintegrity.DataIntegrityProof;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;


/**
 * Holder for W3C's Verifiable Credential
 */
public class W3CVCHolder {
    private JsonLDObject credential;
    private VerifiableCredential.VCVersion version;


    public W3CVCHolder(VerifiableCredential credential) {
        this.version = credential.version;
        switch (credential.version) {
            case VCDMv1p1:
                this.credential = com.danubetech.verifiablecredentials.VerifiableCredential
				    .fromJson(new StringReader(credential.getJson().toString()));
                break;
            case VCDMv2p0:
                this.credential = com.danubetech.verifiablecredentials.VerifiableCredentialV2
                    .fromJson(new StringReader(credential.getJson().toString()));
                break;
            default:
                throw new IllegalArgumentException("Unsupported version: " + credential.version);
        }
        this.credential.setDocumentLoader(new CachingDocumentLoader());
    }

    /**
     * Get the list of proofs in the credential.
     * {@link VerifiableCredential} contains the method getLdProof(), but only works with one proof. This methods
     * returns a list of all proofs defined in the credential.
     * @return proofs defined in the credential
     */
    public List<DataIntegrityProof> getProofs() {
        return JsonLDObjectUtils.getListFromJsonLDObject(DataIntegrityProof.class, credential);
    }

    public JsonLDObject getCredential() {
        return credential;
    }

    public URI getIssuer() {
        switch (version) {
            case VCDMv1p1:
                return ((com.danubetech.verifiablecredentials.VerifiableCredential) credential).getIssuer();
            case VCDMv2p0:
            Object issuer = ((com.danubetech.verifiablecredentials.VerifiableCredentialV2) credential).getIssuer();
            if (issuer instanceof String) {
                return URI.create((String) issuer);
            }
            if (issuer instanceof Map) {
                Map<?, ?> issuerMapRaw = (Map<?, ?>) issuer;
                // Convert to Map<String, Object>
                Map<String, Object> issuerMap = issuerMapRaw.entrySet().stream()
                        .filter(e -> e.getKey() instanceof String)
                        .collect(java.util.stream.Collectors.toMap(
                                e -> (String) e.getKey(),
                                Map.Entry::getValue
                        ));
                String issuerUri = JsonLDUtils.jsonLdGetString(issuerMap, "id");
                return issuerUri != null ? URI.create(issuerUri) : null;
            }
            return null;
            default:
                throw new IllegalArgumentException("Unsupported version: " + version);
        }
    }
}
