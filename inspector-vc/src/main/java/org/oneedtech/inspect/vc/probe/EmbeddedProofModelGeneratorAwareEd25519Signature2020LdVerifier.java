package org.oneedtech.inspect.vc.probe;

import java.util.HexFormat;

import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.verifier.Ed25519Signature2020LdVerifier;

public class EmbeddedProofModelGeneratorAwareEd25519Signature2020LdVerifier
    extends Ed25519Signature2020LdVerifier implements EmbeddedProofModelGenerator {

  private URDNA2015Canonicalizer canonicalizer;

  public EmbeddedProofModelGeneratorAwareEd25519Signature2020LdVerifier(byte[] publicKey) {
    super(publicKey);
  }

  @Override
  public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
    if (canonicalizer == null) {
      canonicalizer = new URDNA2015Canonicalizer(DataIntegrityProof.builder());
    }
    return canonicalizer;
  }

  @Override
  public EmbeddedProofModel getGeneratedObject() {
    EmbeddedProofModel model = new EmbeddedProofModel();

    model.addIntermediateValue(
        "ldProofWithoutProofValues", canonicalizer.getLdProofWithoutProofValues().toJson(true));
    model.addIntermediateValue(
        "jsonLdObjectWithoutProof", canonicalizer.getJsonLdObjectWithoutProof().toJson(true));
    model.addIntermediateValue(
        "canonicalizedLdProofWithoutProofValues",
        canonicalizer.getCanonicalizedLdProofWithoutProofValues());
    model.addIntermediateValue(
        "canonicalizedJsonLdObjectWithoutProof",
        canonicalizer.getCanonicalizedJsonLdObjectWithoutProof());
    model.addIntermediateValue(
        "canonicalizationResult",
        HexFormat.of().formatHex(canonicalizer.getCanonicalizationResult()));

    return model;
  }
}
