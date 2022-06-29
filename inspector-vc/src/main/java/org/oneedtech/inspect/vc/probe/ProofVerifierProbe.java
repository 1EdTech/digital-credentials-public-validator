package org.oneedtech.inspect.vc.probe;

import java.security.KeyFactory;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

/**
 * A Probe that verifies credential proofs 
 * @author mlyon
 */
public class ProofVerifierProbe extends Probe<Credential> {
	
	public ProofVerifierProbe() {
		super(ID);
	}
	
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {

		//TODO @Miles -- if proofs fail, report OutCome.Fatal
								
		return success(ctx);
	}

	public boolean validate(String pubkey, String signature, String timestamp, String message) throws Exception {
		//TODO: continue this implementation.
		//Pulled in bouncy castle library and made sure this sample compiled only.
		final var provider = new BouncyCastleProvider();
		Security.addProvider(provider);
		final var byteKey = Hex.decode(pubkey);
		final var pki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), byteKey);
		final var pkSpec = new X509EncodedKeySpec(pki.getEncoded());
		final var kf = KeyFactory.getInstance("ed25519", provider);
		final var publicKey = kf.generatePublic(pkSpec);
		final var signedData = Signature.getInstance("ed25519", provider);
		signedData.initVerify(publicKey);
		signedData.update(timestamp.getBytes());
		signedData.update(message.getBytes());
		return signedData.verify(Hex.decode(signature));
	}

	public static final String ID = ProofVerifierProbe.class.getSimpleName();
}
