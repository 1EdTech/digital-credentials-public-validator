package org.oneedtech.inspect.vc.verification;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.suites.SignatureSuite;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Ed25519Signature2022SignatureSuite  extends SignatureSuite {

    Ed25519Signature2022SignatureSuite() {

		super(
				"DataIntegrityProof",
				URI.create("https://www.w3.org/TR/vc-di-eddsa"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#ed25519"),
				List.of(KeyTypeName.Ed25519),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				Arrays.asList(LDSecurityContexts.JSONLD_CONTEXT_W3ID_SUITES_ED25519_2022_V1,
                    info.weboftrust.ldsignatures.jsonld.LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}

}
