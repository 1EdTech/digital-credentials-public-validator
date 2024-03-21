package org.oneedtech.inspect.vc;

import java.io.StringReader;
import java.util.List;

import org.oneedtech.inspect.vc.jsonld.JsonLDObjectUtils;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import info.weboftrust.ldsignatures.LdProof;

/**
 * Holder for W3C's Verifiable Credential
 */
public class W3CVCHolder {
    private com.danubetech.verifiablecredentials.VerifiableCredential credential;

    public W3CVCHolder(VerifiableCredential credential) {
        switch (credential.version) {
            case VCDMv1p1:
                this.credential = com.danubetech.verifiablecredentials.VerifiableCredential
				    .fromJson(new StringReader(credential.getJson().toString()));
                break;
            case VCDMv2p0:
                this.credential = W3CVerifiableCredentialDM2
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
    public List<LdProof> getProofs() {
        return JsonLDObjectUtils.getListFromJsonLDObject(LdProof.class, credential);
    }

    public com.danubetech.verifiablecredentials.VerifiableCredential getCredential() {
        return credential;
    }
}
