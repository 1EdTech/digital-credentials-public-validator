package org.oneedtech.inspect.vc.verification;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.verifier.LdVerifier;
import com.danubetech.keyformats.crypto.ByteVerifier;
import com.danubetech.keyformats.crypto.impl.Ed25519_EdDSA_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import io.ipfs.multibase.Multibase;
import java.security.GeneralSecurityException;

public class Ed25519Signature2022LdVerifier extends LdVerifier<Ed25519Signature2022SignatureSuite> {

  public Ed25519Signature2022LdVerifier(ByteVerifier verifier) {

    super(SignatureSuites.SIGNATURE_SUITE_ED25519SIGNATURE2022, verifier);
  }

  public Ed25519Signature2022LdVerifier(byte[] publicKey) {

    this(new Ed25519_EdDSA_PublicKeyVerifier(publicKey));
  }

  public Ed25519Signature2022LdVerifier() {

    this((ByteVerifier) null);
  }

  @Override
  public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
    return new URDNA2015Canonicalizer(Eddsa2022DataIntegrity.builder());
  }

  public static boolean verify(
      byte[] signingInput, DataIntegrityProof dataIntegrityProof, ByteVerifier verifier)
      throws GeneralSecurityException {

    // verify

    String proofValue = dataIntegrityProof.getProofValue();
    if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

    boolean verify;

    byte[] bytes = Multibase.decode(proofValue);
    verify = verifier.verify(signingInput, bytes, JWSAlgorithm.EdDSA);

    // done

    return verify;
  }

  @Override
  public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof)
      throws GeneralSecurityException {

    return verify(signingInput, dataIntegrityProof, this.getVerifier());
  }
}
