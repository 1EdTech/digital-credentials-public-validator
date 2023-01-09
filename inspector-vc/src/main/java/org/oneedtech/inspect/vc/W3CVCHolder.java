package org.oneedtech.inspect.vc;

import java.util.List;

import org.oneedtech.inspect.vc.jsonld.JsonLDObjectUtils;

import com.danubetech.verifiablecredentials.VerifiableCredential;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import info.weboftrust.ldsignatures.LdProof;

/**
 * Holder for W3C's Verifiable Credential
 */
public class W3CVCHolder {
    private VerifiableCredential credential;

    public W3CVCHolder(VerifiableCredential credential) {
        this.credential = credential;
		ConfigurableDocumentLoader documentLoader = new ConfigurableDocumentLoader();
		documentLoader.setEnableHttp(true);
		documentLoader.setEnableHttps(true);
		credential.setDocumentLoader(documentLoader);
    }

    /**
     * Get the list of proofs in the credential.
     * {@link VerifiableCredential} contains the method getLdProof(), but only works with one proof. This methods
     * returns a list of all proofs defined in the credential.
     * @return proofs defined in the credential
     */
    public List<LdProof> getLdProofs() {
        return JsonLDObjectUtils.getListFromJsonLDObject(LdProof.class, credential);
    }

    public VerifiableCredential getCredential() {
        return credential;
    }
}
