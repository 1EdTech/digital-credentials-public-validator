package org.oneedtech.inspect.vc;

import java.io.StringWriter;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.apicatalog.did.Did;
import com.apicatalog.did.key.DidKey;
import com.apicatalog.ld.signature.eddsa.EdDSASignature2022;
import com.apicatalog.ld.signature.key.KeyPair;
import com.apicatalog.vc.integrity.DataIntegrityProofDraft;
import com.apicatalog.vc.issuer.ProofDraft;
import com.apicatalog.vc.keygen.KeysGenerator;
import com.apicatalog.vc.processor.ExpandedVerifiable;
import com.apicatalog.vc.verifier.Verifier;

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


			final Did didKey = DidKey.from(URI.create("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"));

			//https://w3id.org/security#Ed25519KeyPair2020
			//https://w3id.org/security#Ed25519Signature2020
			EdDSASignature2022 suite = new EdDSASignature2022();

			URI unsigned = Samples.OB30.JSON.SIMPLE_JSON_NOPROOF.asURL().toURI();
			KeyPair kp = KeysGenerator.with(EdDSASignature2022.CRYPTO).get();

			ProofDraft options = new DataIntegrityProofDraft(suite,
				EdDSASignature2022.CRYPTO,
				didKey.toUri(),
				URI.create("https://w3id.org/security#assertionMethod"));

			ExpandedVerifiable issuerSignature = suite.createIssuer(kp).sign(unsigned, options);
			System.err.println(pretty(issuerSignature.compacted()));
			JsonObject signed = issuerSignature.compacted();
			JsonObject proof = signed.getJsonObject("sec:proof");
			Assertions.assertNotNull(proof);

			Verifier.with(suite).verify(signed).validate();
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
