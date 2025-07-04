package org.oneedtech.inspect.vc.verification;

import com.danubetech.dataintegrity.jsonld.DataIntegrityContexts;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

public class EcdsaSd2023SignatureSuite extends DataIntegritySuite {

  EcdsaSd2023SignatureSuite() {

    super(
        "DataIntegrityProof",
        URI.create("http://w3id.org/security#ecdsa-sd-2023"),
        Map.of(
            KeyTypeName.P_256,
            List.of(JWSAlgorithm.ES256),
            KeyTypeName.P_384,
            List.of(JWSAlgorithm.ES384)),
        List.of(DataIntegrityContexts.JSONLD_CONTEXT_W3ID_SECURITY_DATAINTEGRITY_V2));
  }

  public ECPublicKey getPublicKeyFromBytes(final byte[] pubKey, String curveName)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
    final KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
    final ECNamedCurveSpec params =
        new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN(), spec.getH());
    final ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
    final ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
    return (ECPublicKey) kf.generatePublic(pubKeySpec);
  }
}
