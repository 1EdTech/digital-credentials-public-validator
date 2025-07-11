package org.oneedtech.inspect.vc.verification;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import java.net.URI;
import java.util.List;
import java.util.Map;

public class Ed25519Signature2022SignatureSuite extends DataIntegritySuite {

  Ed25519Signature2022SignatureSuite() {

    super(
        "DataIntegrityProof",
        URI.create("http://w3id.org/security#ed25519"),
        Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
        List.of(
            DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_DATAINTEGRITY_V2));
  }
}
