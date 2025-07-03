package org.oneedtech.inspect.vc.verification;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import java.net.URI;
import java.util.List;
import java.util.Map;

public class EcdsaSd2023SignatureSuite extends DataIntegritySuite {

  EcdsaSd2023SignatureSuite() {

    super(
        "DataIntegrityProof",
        URI.create("http://w3id.org/security#ecdsa-sd-2023"),
        Map.of(KeyTypeName.P_256, List.of(JWSAlgorithm.ES256), KeyTypeName.P_384, List.of(JWSAlgorithm.ES384)),
        List.of(
            DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_DATAINTEGRITY_V2));
  }
}
