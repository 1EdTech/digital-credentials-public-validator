package org.oneedtech.inspect.vc.probe;

import java.io.StringReader;
import java.net.URI;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.apicatalog.vc.processor.StatusVerifier;
import com.danubetech.verifiablecredentials.VerifiableCredential;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;

/**
 * A Probe that verifies a credential's embedded proof.
 * @author mgylling
 */
public class EmbeddedProofProbe extends Probe<Credential> {
		
	public EmbeddedProofProbe() {
		super(ID);
	}
	
		
	/*
	 * Using verifiable-credentials-java (https://github.com/danubetech/verifiable-credentials-java) 
	 */
	@Override  
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {	
		
		//TODO check that proof is Ed25519 - issue error if not ("type": "Ed25519Signature2020",
		//TODO check value "proofPurpose": "assertionMethod", if not error
		
		VerifiableCredential vc = VerifiableCredential.fromJson(new StringReader(crd.getJson().toString()));
		ConfigurableDocumentLoader documentLoader = new ConfigurableDocumentLoader();
		documentLoader.setEnableHttp(true);
		documentLoader.setEnableHttps(true);
		vc.setDocumentLoader(documentLoader);						
		URI method = vc.getLdProof().getVerificationMethod();

		// The verification method must dereference to an Ed25519VerificationKey2020.
		// Danubetech's Ed25519Signature2020LdVerifier expects the decoded public key
		// from the Ed25519VerificationKey2020 (32 bytes).

		String publicKeyMultibase = "";

		// Formats accepted:
		//
		// [controller]#[publicKeyMultibase]
		// did:key:[publicKeyMultibase]
		// [publicKeyMultibase]

		// TODO fourth format that we don't support yet: a URL that returns a Ed25519VerificationKey2020
		// if starts with http and does not have hashcode, try fetch and see if returns Ed25519VerificationKey2020
		// property is publicKeyMultibase

		publicKeyMultibase = method.toString();
		
        if (method.getFragment() != null) {
            publicKeyMultibase = method.getFragment();
        } else {
            if (method.getScheme().equals("did")) {
                if (method.getSchemeSpecificPart().startsWith("key:")) {
                    publicKeyMultibase = method.getSchemeSpecificPart().substring(4);
                } else {
                    return error("Unknown verification method: " + method, ctx);
                }
            } else if (method.getScheme().equals("http") || method.getScheme().equals("https")) {
                return error("Cannot parse http verification key yet", ctx);
            }
        }

		// Decode the Multibase to Multicodec and check that it is an Ed25519 public key
		// https://w3c-ccg.github.io/di-eddsa-2020/#ed25519verificationkey2020
		byte[] publicKeyMulticodec;
		try {
			publicKeyMulticodec = Multibase.decode(publicKeyMultibase);
			if (publicKeyMulticodec[0] != (byte) 0xed || publicKeyMulticodec[1] != (byte) 0x01) {
				return error("Verification method does not contain an Ed25519 public key", ctx);
			}
		} catch (Exception e) {
			return error("Verification method is invalid: " + e.getMessage(), ctx);
		}

		// Extract the publicKey bytes from the Multicodec
		byte[] publicKey = Multicodec.decode(Codec.Ed25519PublicKey, publicKeyMulticodec);
		
		Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(publicKey); 
		
		//TODO find out whether we also should check that controller matches issuer ID:
		// if [controller]#[publicKeyMultibase] format - check [controller] segment
		// if did:key:[publicKeyMultibase] format: issuer ID must match the entire URI
		// if [publicKeyMultibase] -- don't check issuer ID. Maybe we should warn about this syntax. 
		
		try {
			boolean verify = verifier.verify(vc);
			if (!verify) {
				return error("Embedded proof verification failed.", ctx);
			}
		} catch (Exception e) {
			return fatal("Embedded proof verification failed:" + e.getMessage(), ctx);
		}	
		
		return success(ctx);
	}
	
	
	
	/*
	 * Note: if using com.apicatalog Iron, we get a generic VC verifier that
	 * will test other stuff than the Proof. So sometimes it may be that
	 * Iron internally retests something that we're already testing out in the
	 * Inspector class (e.g. expiration). But use this for now -- and remember
	 * that this probe is only run if the given credential has internal proof 
	 * (aka is not a jwt). 
	 */
	
//	/*
//	 * Using iron-verifiable-credentials (https://github.com/filip26/iron-verifiable-credentials) 
//	 */
//	@Override  
//	public ReportItems run(Credential crd, RunContext ctx) throws Exception {	
//		JsonDocument jsonDoc = JsonDocument.of(new StringReader(crd.getJson().toString()));
//		JsonObject json = jsonDoc.getJsonContent().get().asJsonObject();		
//		try {
//			Vc.verify(json)
//				.loader(new CachingDocumentLoader())
//				.useBundledContexts(false) //we control the cache in the loader
//				.statusVerifier(new IronNoopStatusVerifier()) 
//				//.domain(...) 		
//				//.didResolver(...)									
//				.isValid();
//		} catch (DocumentError e) {
//			return error(e.getType() + " " + e.getSubject(), ctx);
//		} catch (VerificationError e) {
//			//System.err.println(e.getCode() + " (ProofVerifierProbe)");
//			if(e.getCode() == Code.Internal) {
//				return exception(e.getMessage(), ctx.getResource());	
//			} else if(e.getCode().equals(Code.Expired)) {
//				//handled by other probe	
//			} else {
//				return fatal(e.getCode().name() + " " + e.getMessage(), ctx);	
//			}
//			
//		}		
//		return success(ctx);
//	}	
		
	private static final class IronNoopStatusVerifier implements StatusVerifier {
		@Override
		public void verify(Status status) throws DocumentError, VerifyError {
			// noop			
		}		
	}
	
	public static final String ID = EmbeddedProofProbe.class.getSimpleName(); 
}
