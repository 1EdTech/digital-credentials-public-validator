package org.oneedtech.inspect.vc;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.apicatalog.ld.signature.ed25519.Ed25519Proof2020Adapter;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.ld.signature.proof.ProofOptions;
import com.apicatalog.ld.signature.proof.VerificationMethod;
import com.apicatalog.vc.Vc;
import com.apicatalog.vc.processor.Issuer;

import jakarta.json.JsonObject;

public class IronTests {
	
	@Disabled
	@Test
	void testOb_01() {
		Assertions.assertDoesNotThrow(()->{
			URI unsigned = Samples.OB30.JSON.SIMPLE_JSON_NOPROOF.asURL().toURI();			
			KeyPair kp = Vc.generateKeys("https://w3id.org/security#Ed25519Signature2020").get(URI.create("urn:1"), 256);			
			ProofOptions options = ProofOptions.create(
					Ed25519Proof2020Adapter.TYPE, 
					new VerificationMethod(URI.create("did:key:z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj")),
					URI.create("https://w3id.org/security#assertionMethod")).created(Instant.now().truncatedTo(ChronoUnit.SECONDS));
					
			Issuer issuer = Vc.sign(unsigned, kp, options);
			JsonObject signed = issuer.getCompacted();
			JsonObject proof = signed.getJsonObject("sec:proof");
			
			Assertions.assertNotNull(proof);
				
			System.err.println (issuer.getCompacted().toString());
					
			Vc.verify(issuer.getCompacted()).isValid();
		});
	}
	
	@Disabled
	@Test
	void testClr_01() {
		Assertions.assertDoesNotThrow(()->{
			URI unsigned = Samples.CLR20.JSON.SIMPLE_JSON_NOPROOF.asURL().toURI();			
			KeyPair kp = Vc.generateKeys("https://w3id.org/security#Ed25519Signature2020").get(URI.create("urn:1"), 256);
			ProofOptions options = ProofOptions.create(
					Ed25519Proof2020Adapter.TYPE, 
					new VerificationMethod(URI.create("did:key:z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj")),
					URI.create("https://w3id.org/security#assertionMethod"));
					
			Issuer issuer = Vc.sign(unsigned, kp, options);
			JsonObject job = issuer.getCompacted().getJsonObject("sec:proof");
			
			//System.err.println (issuer.getCompacted().toString());			
			Assertions.assertNotNull(job);			
			Vc.verify(issuer.getCompacted()).isValid();
		});
	}
}
