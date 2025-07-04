package org.oneedtech.inspect.vc.probe;

import com.apicatalog.jsonld.StringUtils;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.multibase.MultibaseDecoder;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.MulticodecDecoder;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.canonicalizer.URDNA2015SHA256Canonicalizer;
import com.danubetech.dataintegrity.verifier.Ed25519Signature2020LdVerifier;
import com.danubetech.dataintegrity.verifier.LdVerifier;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import java.net.URI;
import java.security.spec.InvalidKeySpecException;
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
import org.oneedtech.inspect.vc.verification.EcdsaSd2023LdVerifier;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022LdVerifier;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022VCDM20LdVerifier;
import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

/**
 * A Probe that verifies a credential's embedded proof.
 *
 * @author mgylling
 */
public class EmbeddedProofProbe extends Probe<VerifiableCredential> {

  private static final List<String> ALLOWED_CRYPTOSUITES =
      List.of("eddsa-2022", "eddsa-rdfc-2022", "ecdsa-sd-2023");
  private MulticodecDecoder multicodecDecoder;

  public EmbeddedProofProbe() {
    super(ID);
    this.multicodecDecoder =
        MulticodecDecoder.getInstance(
            KeyCodec.ED25519_PUBLIC_KEY, KeyCodec.P256_PUBLIC_KEY, KeyCodec.P384_PUBLIC_KEY);
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
          DidResolution didResolution =
              didResolver.resolve(method, credentialHolder.getCredential().getDocumentLoader());
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

    // Decode the Multibase to Multicodec and check that it is an Ed25519, P256 or P384 public key
    // https://www.w3.org/TR/vc-di-eddsa/#multikey && https://www.w3.org/TR/vc-di-ecdsa/#multikey
    if (!IsValidPublicKeyMultibase(publicKeyMultibase)) {
      return error(
          "Verification method does not contain either an Ed25519, P256 or P384 public key", ctx);
    }

    byte[] publicKeyMulticodec = MultibaseDecoder.getInstance().decode(publicKeyMultibase);
    Multicodec codec = multicodecDecoder.getCodec(publicKeyMulticodec).get();

    URI credentialIssuer = credentialHolder.getIssuer();
    if (controller != null && credentialIssuer != null) {
      if (!controller.equals(credentialIssuer.toString())) {
        return error("Key controller does not match issuer: " + credentialIssuer, ctx);
      }
    }

    // Extract the publicKey bytes from the Multicodec
    byte[] publicKey = multicodecDecoder.decode(publicKeyMulticodec);

    try {
      // choose verifier
      LdVerifier<?> verifier = getVerifier(proof, publicKey, crd, codec);

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
            return error(
                "Embedded proof verification failed. You can see intermediate results for proof"
                    + " calculations by downloading the report.",
                modelGenerator.getGeneratedObject(),
                ctx);
          }
        }
        return error("Embedded proof verification failed.", ctx);
      }
    } catch (Throwable e) {
      return fatal("Embedded proof verification failed: " + e.getMessage(), ctx);
    }

    return success(ctx);
  }

  private LdVerifier<?> getVerifier(
      DataIntegrityProof proof, byte[] publicKey, VerifiableCredential crd, Multicodec codec)
      throws Throwable, InvalidKeySpecException {
    // backwards compatibility for Ed25519Signature2020
    if (proof.isType("Ed25519Signature2020")) {
      return new Ed25519Signature2020LdVerifier(publicKey);
    }
    if (proof.isType("DataIntegrityProof")) {
      // get cryptosuite from proof
      String cryptosuite = proof.getJsonObject().get("cryptosuite").toString();
      if ("ecdsa-sd-2023".equals(cryptosuite)) {
        return new EcdsaSd2023LdVerifier(publicKey, codec);
      }
      if (crd.getVersion() == VerifiableCredential.VCVersion.VCDMv1p1) {
        return new Ed25519Signature2022LdVerifier(publicKey);
      }
      return new Ed25519Signature2022VCDM20LdVerifier(publicKey);
    }
    throw new IllegalArgumentException(
        "Unsupported proof type: "
            + proof.getType()
            + ". Supported types are: Ed25519Signature2020, DataIntegrityProof");
  }

  private Boolean IsValidPublicKeyMultibase(String publicKeyMultibase) {
    try {
      byte[] publicKeyMulticodec = MultibaseDecoder.getInstance().decode(publicKeyMultibase);
      return multicodecDecoder.getCodec(publicKeyMulticodec).isPresent();
    } catch (Exception e) {
      return false;
    }
  }

  protected ReportItems error(String msg, GeneratedObject object, RunContext context) {
    return new ReportItems(List.of(error(msg, context).iterator().next()), List.of(object));
  }

  public static final String ID = EmbeddedProofProbe.class.getSimpleName();
}
