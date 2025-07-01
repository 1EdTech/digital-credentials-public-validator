package org.oneedtech.inspect.vc.probe;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.W3CVCHolder;
import org.oneedtech.inspect.vc.probe.did.DidResolution;
import org.oneedtech.inspect.vc.probe.did.DidResolutionException;
import org.oneedtech.inspect.vc.probe.did.DidResolver;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022LdVerifier;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022VCDM20LdVerifier;
import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

import com.apicatalog.jsonld.StringUtils;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.verifier.Ed25519Signature2020LdVerifier;
import com.danubetech.dataintegrity.verifier.LdVerifier;

import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;

/**
 * A Probe that verifies a credential's embedded proof.
 *
 * @author mgylling
 */
public class EmbeddedProofProbe extends Probe<VerifiableCredential> {

  private static final List<String> ALLOWED_CRYPTOSUITES = List.of("eddsa-2022", "eddsa-rdfc-2022");

  public EmbeddedProofProbe() {
    super(ID);
  }

  /*
   * Using verifiable-credentials-java from Danubetech
   * (https://github.com/danubetech/verifiable-credentials-java)
   */
  @Override
  public ReportItems run(VerifiableCredential crd, RunContext ctx) throws Exception {

    W3CVCHolder credentialHolder = new W3CVCHolder(crd);

    List<DataIntegrityProof> proofs = credentialHolder.getProofs();
    if (proofs == null || proofs.size() == 0) {
      return error("The verifiable credential is missing a proof.", ctx);
    }

    // get proof of standard type and purpose
    Optional<DataIntegrityProof> selectedProof =
        proofs.stream()
            .filter(proof -> proof.getProofPurpose().equals("assertionMethod"))
            .filter(
                proof ->
                    proof.isType("Ed25519Signature2020")
                        || (proof.isType("DataIntegrityProof")
                            && proof.getJsonObject().containsKey("cryptosuite")
                            && ALLOWED_CRYPTOSUITES.contains(
                                proof.getJsonObject().get("cryptosuite"))))
            .findFirst();

    if (!selectedProof.isPresent()) {
      return error(
          "No proof with type any of (\"Ed25519Signature2020\", \"DataIntegrityProof\" with"
              + " cryptosuite attr of \"eddsa-rdfc-2022\" or \"eddsa-2022\") or proof purpose"
              + " \"assertionMethod\" found",
          ctx);
    }

    DataIntegrityProof proof = selectedProof.get();

    URI method = proof.getVerificationMethod();

    // The verification method must dereference to an Ed25519VerificationKey2020.
    // Danubetech's Ed25519Signature2020LdVerifier expects the decoded public key
    // from the Ed25519VerificationKey2020 (32 bytes).
    //
    // Formats accepted:
    //
    // [controller]#[publicKeyMultibase]
    // did:key:[publicKeyMultibase]
    // did:web:[url-encoded domain-name][:path]*
    // http/s://[location of a Ed25519VerificationKey2020 document]
    // http/s://[location of a controller document with a 'verificationMethod' with
    // a Ed25519VerificationKey2020]

    String publicKeyMultibase;
    String controller = null;

    publicKeyMultibase = method.toString();

    if (method.getFragment() != null && IsValidPublicKeyMultibase(method.getFragment())) {
      publicKeyMultibase = method.getFragment();
      controller = method.toString().substring(0, method.toString().indexOf("#"));
    } else {
      if (StringUtils.isBlank(method.getScheme())) {
        return error("The verification method must be a valid URI (missing scheme)", ctx);
      } else if (method.getScheme().equals("did")) {
        DidResolver didResolver = ctx.get(RunContextKey.DID_RESOLVER);
        try {
          DidResolution didResolution = didResolver.resolve(method, credentialHolder.getCredential().getDocumentLoader());
          publicKeyMultibase = didResolution.getPublicKeyMultibase();
          controller = didResolution.getController();
        } catch (DidResolutionException e) {
          return error(e.getMessage(), ctx);
        }
      } else if (method.getScheme().equals("http") || method.getScheme().equals("https")) {
        try {
          Document keyDocument =
              credentialHolder
                  .getCredential()
                  .getDocumentLoader()
                  .loadDocument(method, new DocumentLoaderOptions());
          Optional<JsonStructure> keyStructure = keyDocument.getJsonContent();
          if (keyStructure.isEmpty()) {
            return error("Key document not found at " + method, ctx);
          }

          // First look for a Ed25519VerificationKey2020 document
          controller = keyStructure.get().asJsonObject().getString("controller");
          if (StringUtils.isBlank(controller)) {
            // Then look for a controller document (e.g. DID Document) with a
            // 'verificationMethod'
            // that is a Ed25519VerificationKey2020 document
            JsonObject keyVerificationMethod =
                keyStructure.get().asJsonObject().getJsonObject("verificationMethod");
            if (keyVerificationMethod.isEmpty()) {
              return error("Cannot parse key document from " + method, ctx);
            }
            controller = keyVerificationMethod.getString("controller");
            publicKeyMultibase = keyVerificationMethod.getString("publicKeyMultibase");
          } else {
            publicKeyMultibase = keyStructure.get().asJsonObject().getString("publicKeyMultibase");
          }

        } catch (Exception e) {
          return error("Invalid verification key URL: " + e.getMessage(), ctx);
        }
      } else {
        return error("Unknown verification method scheme: " + method.getScheme(), ctx);
      }
    }

    // Decode the Multibase to Multicodec and check that it is an Ed25519 public key
    // https://w3c-ccg.github.io/di-eddsa-2020/#ed25519verificationkey2020
    byte[] publicKeyMulticodec;
    try {
      publicKeyMulticodec = MultibaseDecoder.getInstance().decode(publicKeyMultibase);
      if (publicKeyMulticodec[0] != (byte) 0xed || publicKeyMulticodec[1] != (byte) 0x01) {
        return error("Verification method does not contain an Ed25519 public key", ctx);
      }
    } catch (Exception e) {
      return error("Invalid public key: " + e.getMessage(), ctx);
    }

    URI credentialIssuer = credentialHolder.getIssuer();
    if (controller != null && credentialIssuer != null) {
      if (!controller.equals(credentialIssuer.toString())) {
        return error(
            "Key controller does not match issuer: " + credentialIssuer,
            ctx);
      }
    }

    // Extract the publicKey bytes from the Multicodec
    byte[] publicKey = MulticodecDecoder.getInstance(KeyCodec.ED25519_PUBLIC_KEY).decode(publicKeyMulticodec);

    // choose verifier
    LdVerifier<?> verifier = getVerifier(proof, publicKey, crd);

    try {
      boolean verify = verifier.verify(credentialHolder.getCredential(), proof);
      if (!verify) {
        // add proof calculations to the report
        Canonicalizer canonicalizer = verifier.getCanonicalizer(proof);
        if (canonicalizer != null) {
          URDNA2015Canonicalizer urdna2015Canonicalizer = null;
          if (canonicalizer instanceof URDNA2015Canonicalizer) {
            urdna2015Canonicalizer = (URDNA2015Canonicalizer) canonicalizer;
          } else if (canonicalizer instanceof URDNA2015SHA256Canonicalizer) {
            urdna2015Canonicalizer = new URDNA2015Canonicalizer(DataIntegrityProof.builder());
          }
          if (urdna2015Canonicalizer != null) {
            // canonicalize the proof and credential again to store intermediate results
            urdna2015Canonicalizer.canonicalize(proof, credentialHolder.getCredential());

            EmbeddedProofModelGenerator modelGenerator =
                new EmbeddedProofModelGenerator(urdna2015Canonicalizer);
            return error("Embedded proof verification failed. You can see intermediate results for proof calculations by downloading the report.", modelGenerator.getGeneratedObject(), ctx);
          }
        }
        return error("Embedded proof verification failed.", ctx);
      }
    } catch (Exception e) {
      return fatal("Embedded proof verification failed: " + e.getMessage(), ctx);
    }

    return success(ctx);
  }

  private LdVerifier<?> getVerifier(DataIntegrityProof proof, byte[] publicKey, VerifiableCredential crd) {
    return proof.isType("Ed25519Signature2020")
        ? new Ed25519Signature2020LdVerifier(publicKey)
        : crd.getVersion() == VerifiableCredential.VCVersion.VCDMv1p1
            ? new Ed25519Signature2022LdVerifier(publicKey)
            : new Ed25519Signature2022VCDM20LdVerifier(publicKey);
  }

  private Boolean IsValidPublicKeyMultibase(String publicKeyMultibase) {
    try {
      byte[] publicKeyMulticodec = MultibaseDecoder.getInstance().decode(publicKeyMultibase);
      byte[] publicKey = MulticodecDecoder.getInstance(KeyCodec.ED25519_PUBLIC_KEY).decode(publicKeyMulticodec);
      return publicKey.length == 32;
    } catch (Exception e) {
      return false;
    }
  }

  protected ReportItems error(String msg, GeneratedObject object, RunContext context) {
    return new ReportItems(List.of(error(msg, context).iterator().next()), List.of(object));
  }

  public static final String ID = EmbeddedProofProbe.class.getSimpleName();
}
