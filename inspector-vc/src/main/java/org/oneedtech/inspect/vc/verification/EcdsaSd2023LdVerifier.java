package org.oneedtech.inspect.vc.verification;

import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA384Canonicalizer;
import com.danubetech.dataintegrity.verifier.LdVerifier;
import com.danubetech.keyformats.crypto.impl.P_256_ES256_PublicKeyVerifier;
import com.danubetech.keyformats.crypto.impl.P_384_ES384_PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.vc.verification.SDFunctions.VerifyData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EcdsaSd2023LdVerifier extends LdVerifier<EcdsaSd2023SignatureSuite> {

  private static final Logger log = LoggerFactory.getLogger(EcdsaSd2023LdVerifier.class);

  private Multicodec codec;

  private VerifyData verifyData;

  public EcdsaSd2023LdVerifier(byte[] publicKey, Multicodec codec)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    super(SignatureSuites.SIGNATURE_SUITE_ECDSA_SD_2023, null);
    this.codec = codec;
    updateVerifier(publicKey);
  }

  private void updateVerifier(byte[] pubKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    // determine the key type
    if (codec == KeyCodec.P256_PUBLIC_KEY) {
      setVerifier(new P_256_ES256_PublicKeyVerifier(getPublicKeyFromBytes(pubKey, "secp256r1")));
    } else if (codec == KeyCodec.P384_PUBLIC_KEY) {
      setVerifier(new P_384_ES384_PublicKeyVerifier(getPublicKeyFromBytes(pubKey, "secp384r1")));
    } else {
      throw new IllegalArgumentException("Unsupported codec: " + codec);
    }
  }

  private ECPublicKey getPublicKeyFromBytes(final byte[] pubKey, String curveName)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
    final KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
    final ECNamedCurveSpec params =
        new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
    final ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
    final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
    return (ECPublicKey) kf.generatePublic(pubKeySpec);
  }

  public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
    if (codec == KeyCodec.P256_PUBLIC_KEY) {
      return new URDNA2015SHA256Canonicalizer();
    } else if (codec == KeyCodec.P384_PUBLIC_KEY) {
      return new URDNA2015SHA384Canonicalizer();
    }
    throw new IllegalArgumentException("Unsupported codec: " + codec);
  }

  public boolean verify(JsonLDObject jsonLdObject, DataIntegrityProof dataIntegrityProof)
      throws IOException, GeneralSecurityException, JsonLDException {
    // 1. Let unsecuredDocument be a copy of document with the proof value removed.
    JsonLDObject unsecuredDocument = JsonLDObject.builder().base(jsonLdObject).build();
    DataIntegrityProof.removeFromJsonLdObject(unsecuredDocument);

    // 2. Initialize baseSignature, proofHash, publicKey, signatures, nonMandatory, and
    // mandatoryHash to the values associated with their property names in the object returned when
    // calling the algorithm in Section 3.5.9 createVerifyData, passing the document, proof, and any
    // custom JSON-LD API options, such as a document loader.
    SDFunctions sdf = new SDFunctions(getCanonicalizer(dataIntegrityProof), codec);
    verifyData =
        sdf.createVerifyData(
            unsecuredDocument, dataIntegrityProof, jsonLdObject.getDocumentLoader());

    // 3. If the length of signatures does not match the length of nonMandatory, an error MUST be
    // raised and SHOULD convey an error type of PROOF_VERIFICATION_ERROR, indicating that the
    // signature count does not match the non-mandatory message count.
    if (!verifyData.sameLength()) {
      throw new GeneralSecurityException(
          "Signature count does not match the non-mandatory message count.");
    }

    // 4. Initialize publicKeyBytes to the public key bytes expressed in publicKey. Instructions on
    // how to decode the public key value can be found in Section 2.1.1 Multikey.
    updateVerifier(codec.decode(verifyData.getPublicKey()));

    // 5. Initialize toVerify to the result of calling the algorithm in Setion 3.5.1
    // serializeSignData, passing proofHash, publicKey, and mandatoryHash.
    byte[] toVerify =
        sdf.serializeSignData(verifyData.getProofHash(), verifyData.getPublicKey(), verifyData.getMandatoryHash());

    // 6. Initialize verified to true.
    boolean verified = true;

    // 7. Initialize verificationCheck be the result of applying the verification algorithm of the
    // Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with toVerify as the data to
    // be verified against the baseSignature using the public key specified by publicKeyBytes. If
    // verificationCheck is false, set verified to false.

    boolean verificationCheck = verifySignature(toVerify, verifyData.getBaseSignature());
    if (!verificationCheck) {
      verified = false;
    }

    // 8. For every entry (index, signature) in signatures, verify every signature for every
    // selectively disclosed (non-mandatory) statement:

    // 8.1. Initialize verificationCheck to the result of applying the verification algorithm
    // Elliptic Curve Digital Signature Algorithm (ECDSA) [FIPS-186-5], with the UTF-8
    // representation of the value at index of nonMandatory as the data to be verified against
    // signature using the public key specified by publicKeyBytes.
    for (int i = 0; i < verifyData.getNonMandatory().size(); i++) {
      byte[] signature = verifyData.getSignatures().get(i);
      String data = verifyData.getNonMandatory().get(i);
      verificationCheck = verifySignature(data.getBytes(UTF_8), signature);
      // 8.2. If verificationCheck is false, set verified to false.
      if (!verificationCheck) {
        verified = false;
      }
    }

    return verified;
  }

  private boolean verifySignature(byte[] signingInput, byte[] signature)
      throws GeneralSecurityException {

    System.out.println("Verifying data " + new String(Hex.encode(signingInput)) + " with signature: " + new String(Hex.encode(signature)));
    return getVerifier().verify(signingInput, signature, JWSAlgorithm.ES256);
  }

  @Override
  public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof)
      throws GeneralSecurityException {
    throw new UnsupportedOperationException(
        "Verification not supported for ECDSA SD 2023 LD Verifier");
  }
}
