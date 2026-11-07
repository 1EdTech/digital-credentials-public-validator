package org.oneedtech.inspect.vc.verification;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;

import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * The {@code bbs-2023} Data Integrity cryptosuite, https://www.w3.org/TR/vc-di-bbs/.
 *
 * <p>Verification methods use the {@code Multikey} type over a BLS12-381 G2 public key. There is
 * no danubetech/JOSE algorithm identifier for the IETF BBS signature scheme (only the older,
 * incompatible BBS+ scheme has one, {@link JWSAlgorithm#BBSPlus}); it is reused here purely as an
 * inert map key; nothing in {@link Bbs2023LdVerifier} consults it, since verification is
 * implemented directly against {@link org.oneedtech.inspect.vc.verification.bbs.BbsScheme}.
 */
public class Bbs2023SignatureSuite extends DataIntegritySuite {

  Bbs2023SignatureSuite() {
    super(
        "DataIntegrityProof",
        URI.create("https://w3id.org/security#bbs-2023"),
        Map.of(KeyTypeName.Bls12381G2, List.of(JWSAlgorithm.BBSPlus)),
        List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_DATAINTEGRITY_V2));
  }
}
