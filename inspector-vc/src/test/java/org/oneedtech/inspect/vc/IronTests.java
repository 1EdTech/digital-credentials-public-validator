package org.oneedtech.inspect.vc;

import java.io.StringWriter;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.apicatalog.did.key.DidKey;
import com.apicatalog.ld.signature.ed25519.Ed25519Proof2020Adapter;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.ld.signature.proof.ProofOptions;
import com.apicatalog.ld.signature.proof.VerificationMethod;
import com.apicatalog.vc.Vc;
import com.apicatalog.vc.processor.Issuer;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonWriter;
import jakarta.json.JsonWriterFactory;
import jakarta.json.stream.JsonGenerator;

public class IronTests {

	@Disabled
	@Test
	void testOb_01() {
		Assertions.assertDoesNotThrow(()->{


			final DidKey didKey = DidKey.from(URI.create("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"));

			//https://w3id.org/security#Ed25519KeyPair2020
			//https://w3id.org/security#Ed25519Signature2020
			URI unsigned = Samples.OB30.JSON.SIMPLE_JSON_NOPROOF.asURL().toURI();
			KeyPair kp = Vc.generateKeys("https://w3id.org/security#Ed25519Signature2020").get(URI.create("urn:1"), 256);
			ProofOptions options = ProofOptions.create(
					Ed25519Proof2020Adapter.TYPE,
					//new VerificationMethod(URI.create("did:key:z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj")),
					new VerificationMethod(didKey.toUri()),
					URI.create("https://w3id.org/security#assertionMethod")).created(Instant.now().truncatedTo(ChronoUnit.SECONDS));

			Issuer issuer = Vc.sign(unsigned, kp, options);
			System.err.println(pretty(issuer.getCompacted()));
			JsonObject signed = issuer.getCompacted();
			JsonObject proof = signed.getJsonObject("sec:proof");
			Assertions.assertNotNull(proof);

			Vc.verify(issuer.getCompacted()).isValid();
		});
	}

	String pretty(JsonObject jobj) {
		Map<String, Object> properties = new HashMap<>(1);
        properties.put(JsonGenerator.PRETTY_PRINTING, true);
        StringWriter sw = new StringWriter();
        JsonWriterFactory writerFactory = Json.createWriterFactory(properties);
        JsonWriter jsonWriter = writerFactory.createWriter(sw);
        jsonWriter.writeObject(jobj);
        jsonWriter.close();
        return sw.toString();
	}
}
