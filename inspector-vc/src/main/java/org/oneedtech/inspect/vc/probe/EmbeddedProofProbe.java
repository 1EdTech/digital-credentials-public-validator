package org.oneedtech.inspect.vc.probe;

import java.io.StringReader;
import java.net.URI;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;

import com.apicatalog.jsonld.StringUtils;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Codec;
import com.danubetech.verifiablecredentials.VerifiableCredential;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

/**
 * A Probe that verifies a credential's embedded proof.
 *
 * @author mgylling
 */
public class EmbeddedProofProbe extends Probe<Credential> {

	public EmbeddedProofProbe() {
		super(ID);
	}

	/*
	 * Using verifiable-credentials-java from Danubetech
	 * (https://github.com/danubetech/verifiable-credentials-java)
	 */
	@Override
	public ReportItems run(Credential crd, RunContext ctx) throws Exception {

		// TODO: What there are multiple proofs?

		VerifiableCredential vc = VerifiableCredential.fromJson(new StringReader(crd.getJson().toString()));
		ConfigurableDocumentLoader documentLoader = new ConfigurableDocumentLoader();
		documentLoader.setEnableHttp(true);
		documentLoader.setEnableHttps(true);
		vc.setDocumentLoader(documentLoader);

		LdProof proof = vc.getLdProof();
		if (proof == null) {
			return error("The verifiable credential is missing a proof.", ctx);
		}
		if (!proof.isType("Ed25519Signature2020")) {
			return error("Unknown proof type: " + proof.getType(), ctx);
		}
		if (!proof.getProofPurpose().equals("assertionMethod")) {
			return error("Invalid proof purpose: " + proof.getProofPurpose(), ctx);
		}

		URI method = proof.getVerificationMethod();

		// The verification method must dereference to an Ed25519VerificationKey2020.
		// Danubetech's Ed25519Signature2020LdVerifier expects the decoded public key
		// from the Ed25519VerificationKey2020 (32 bytes).

		String publicKeyMultibase;
		String controller = null;

		// Formats accepted:
		//
		// [controller]#[publicKeyMultibase]
		// did:key:[publicKeyMultibase]
		// http/s://[location of a Ed25519VerificationKey2020 document]
		// http/s://[location of a controller document with a 'verificationMethod' with a Ed25519VerificationKey2020]
		// [publicKeyMultibase]

		publicKeyMultibase = method.toString();

		if (method.getFragment() != null) {
			publicKeyMultibase = method.getFragment();
			controller = method.toString().substring(0, method.toString().indexOf("#"));
		} else {
			if (method.getScheme().equals("did")) {
				if (method.getSchemeSpecificPart().startsWith("key:")) {
					publicKeyMultibase = method.getSchemeSpecificPart().substring(4);
				} else {
					return error("Unknown verification method: " + method, ctx);
				}
			} else if (method.getScheme().equals("http") || method.getScheme().equals("https")) {
				// TODO: Can we use proof.getDocumentLoader()?
				ConfigurableDocumentLoader keyDocumentLoader = new ConfigurableDocumentLoader();
				keyDocumentLoader.setEnableHttp(true);
				keyDocumentLoader.setEnableHttps(true);

				Document keyDocument = keyDocumentLoader.loadDocument(method, new DocumentLoaderOptions());
				Optional<JsonStructure> keyStructure = keyDocument.getJsonContent();
				if (keyStructure.isEmpty()) {
					return error("Key document not found at " + method, ctx);
				}

				// First look for a Ed25519VerificationKey2020 document
				controller = keyStructure.get().asJsonObject().getString("controller");
				if (StringUtils.isBlank(controller)) {
					// Then look for a controller document (e.g. DID Document) with a 'verificationMethod'
					// that is a Ed25519VerificationKey2020 document
					JsonObject keyVerificationMethod = keyStructure.get().asJsonObject()
							.getJsonObject("verificationMethod");
					if (keyVerificationMethod.isEmpty()) {
						return error("Cannot parse key document from " + method, ctx);
					}
					controller = keyVerificationMethod.getString("controller");
					publicKeyMultibase = keyVerificationMethod.getString("publicKeyMultibase");
				} else {
					publicKeyMultibase = keyStructure.get().asJsonObject().getString("publicKeyMultibase");
				}
			}
		}

		// Decode the Multibase to Multicodec and check that it is an Ed25519 public key
		// https://w3c-ccg.github.io/di-eddsa-2020/#ed25519verificationkey2020
		byte[] publicKeyMulticodec;
		try {
			publicKeyMulticodec = Multibase.decode(publicKeyMultibase);
			if (publicKeyMulticodec[0] != (byte) 0xed || publicKeyMulticodec[1] != (byte) 0x01) {
				return error("Verification method does not contain an Ed25519 public key", ctx);
			}
		} catch (Exception e) {
			return error("Invalid public key: " + e.getMessage(), ctx);
		}

		if (controller != null) {
			if (!controller.equals(vc.getIssuer().toString())) {
				return error("Key controller does not match issuer: " + vc.getIssuer(), ctx);
			}
		}

		// Extract the publicKey bytes from the Multicodec
		byte[] publicKey = Multicodec.decode(Codec.Ed25519PublicKey, publicKeyMulticodec);

		Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(publicKey);

		try {
			boolean verify = verifier.verify(vc);
			if (!verify) {
				return error("Embedded proof verification failed.", ctx);
			}
		} catch (Exception e) {
			return fatal("Embedded proof verification failed: " + e.getMessage(), ctx);
		}

		return success(ctx);
	}

	public static final String ID = EmbeddedProofProbe.class.getSimpleName();
}
