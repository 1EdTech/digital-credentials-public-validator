package org.oneedtech.inspect.vc;

import java.util.List;

import org.oneedtech.inspect.vc.jsonld.JsonLDObjectUtils;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.danubetech.verifiablecredentials.VerifiableCredential;

import info.weboftrust.ldsignatures.LdProof;

/**
 * Holder for W3C's Verifiable Credential
 */
public class W3CVCHolder {
    private VerifiableCredential credential;

    public W3CVCHolder(VerifiableCredential credential) {
        this.credential = credential;
        credential.setDocumentLoader(new CachingDocumentLoader());
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

    public VerifiableCredential getCredential() {
        return credential;
    }
}
