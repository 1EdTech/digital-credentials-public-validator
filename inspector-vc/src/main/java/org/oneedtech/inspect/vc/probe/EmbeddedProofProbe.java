package org.oneedtech.inspect.vc.probe;

import java.io.StringReader;
import java.net.URI;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.ld.DocumentError;
import com.apicatalog.vc.processor.StatusVerifier;
import com.danubetech.verifiablecredentials.VerifiableCredential;

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
		
		VerifiableCredential vc = VerifiableCredential.fromJson(new StringReader(crd.getJson().toString()));
		vc.setDocumentLoader(new CachingDocumentLoader()); 
						
		URI method = vc.getLdProof().getVerificationMethod();
		byte[] publicKey = method.toString().getBytes(); 
		
		Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(publicKey); 
		
		try {
			verifier.verify(vc);
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
