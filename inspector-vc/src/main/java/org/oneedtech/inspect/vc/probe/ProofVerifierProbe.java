package org.oneedtech.inspect.vc.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.ld.DocumentError;
import com.apicatalog.ld.signature.VerificationError;
import com.apicatalog.vc.Vc;
import com.apicatalog.vc.processor.StatusVerifier;

import jakarta.json.JsonObject;

/**
 * A Probe that verifies a credential's proof.
 * @author mgylling
 */
public class ProofVerifierProbe extends Probe<Credential> {
	
	/*
	 * Note: using com.apicatalog Iron, we get a generic VC verifier that
	 * will test other stuff than the Proof. So sometimes it may be that
	 * Iron internally retests something that we're already testing out in the
	 * Inspector class (e.g. expiration). But use this for now -- and remember
	 * that this probe is only run if the given credential has internal proof 
	 * (aka is not a jwt). 
	 */
	
	public ProofVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {	
		JsonDocument jsonDoc = JsonDocument.of(new StringReader(crd.getJson().toString()));
		JsonObject json = jsonDoc.getJsonContent().get().asJsonObject();		
		try {
			Vc.verify(json)
				.loader(new CachingDocumentLoader())
				.useBundledContexts(false) //we control the cache in the loader
				//.statusVerifier(new NoopStatusVerifier()) 
				//.domain(...) 		
				//.didResolver(...)									
				.isValid();
		} catch (DocumentError e) {
			return error(e.getType() + " " + e.getSubject(), ctx);
		} catch (VerificationError e) {
			return error(e.getCode().name() + " " + e.getMessage(), ctx);
		}		
		return success(ctx);
	}	
		
	private static final class NoopStatusVerifier implements StatusVerifier {
		@Override
		public void verify(Status status) throws DocumentError, VerifyError {
			// noop			
		}		
	}
	
	public static final String ID = ProofVerifierProbe.class.getSimpleName(); 
}
