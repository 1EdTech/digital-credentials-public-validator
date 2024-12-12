package org.oneedtech.inspect.vc.probe;

import com.apicatalog.jsonld.StringUtils;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.apicatalog.multibase.Multibase;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.Multicodec.Codec;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.Canonicalizer;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import info.weboftrust.ldsignatures.verifier.LdVerifier;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.oneedtech.inspect.core.location.Location;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItem;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.W3CVCHolder;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022LdVerifier;
import org.oneedtech.inspect.vc.verification.Ed25519Signature2022VCDM20LdVerifier;
import org.oneedtech.inspect.vc.verification.URDNA2015Canonicalizer;

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

    List<LdProof> proofs = credentialHolder.getProofs();
    if (proofs == null || proofs.size() == 0) {
      return error("The verifiable credential is missing a proof.", ctx);
    }

    // get proof of standard type and purpose
    Optional<LdProof> selectedProof =
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

    LdProof proof = selectedProof.get();

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
        if (method.getSchemeSpecificPart().startsWith("key:")) {
          publicKeyMultibase = method.getSchemeSpecificPart().substring("key:".length());
        } else if (method.getSchemeSpecificPart().startsWith("web:")) {
          String methodSpecificId = method.getRawSchemeSpecificPart().substring("web:".length());

          // read algorithm at https://w3c-ccg.github.io/did-method-web/#read-resolve.
          // Steps in comments

          // 1. Replace ":" with "/" in the method specific identifier to obtain the fully
          // qualified domain name and optional path.
          methodSpecificId = methodSpecificId.replaceAll(":", "/");

          // 2. If the domain contains a port percent decode the colon.
          String portPercentEncoded = URLEncoder.encode(":", Charset.forName("UTF-8"));
          int index = methodSpecificId.indexOf(portPercentEncoded);
          if (index >= 0 && index < methodSpecificId.indexOf("/")) {
            methodSpecificId = methodSpecificId.replace(portPercentEncoded, ":");
          }

          // 3. Generate an HTTPS URL to the expected location of the DID document by
          // prepending https://.
          URI uri = new URI("https://" + methodSpecificId);

          // 4. If no path has been specified in the URL, append /.well-known.
          if (uri.getPath() == null) {
            uri = uri.resolve("/well-known");
          }

          // 5. Append /did.json to complete the URL.
          uri = uri.resolve(uri.getPath() + "/did.json");

          // 6. Perform an HTTP GET request to the URL using an agent that can
          // successfully negotiate a secure HTTPS connection, which enforces the security
          // requirements as described in 2.6 Security and privacy considerations.
          // 7. When performing the DNS resolution during the HTTP GET request, the client
          // SHOULD utilize [RFC8484] in order to prevent tracking of the identity being
          // resolved.
          Optional<JsonStructure> keyStructure;
          try {
            Document keyDocument =
                credentialHolder
                    .getCredential()
                    .getDocumentLoader()
                    .loadDocument(uri, new DocumentLoaderOptions());
            keyStructure = keyDocument.getJsonContent();
          } catch (Exception e) {
            return error(
                "Key document not found at "
                    + method
                    + ". URI: "
                    + uri
                    + " doesn't return a valid document. Reason: "
                    + e.getMessage()
                    + " ",
                ctx);
          }
          if (keyStructure.isEmpty()) {
            return error(
                "Key document not found at "
                    + method
                    + ". URI: "
                    + uri
                    + " doesn't return a valid document. Reason: The document is empty.",
                ctx);
          }

          // check did in "assertionMethod"
          JsonArray assertionMethod =
              keyStructure.get().asJsonObject().getJsonArray("assertionMethod");
          if (assertionMethod == null) {
            return error("Document doesn't have a list of assertion methods at URI: " + uri, ctx);
          } else {
            Boolean anyMatch = false;
            for (int i = 0; i < assertionMethod.size(); i++) {
              String assertionMethodValue = assertionMethod.getString(i);
              if (assertionMethodValue.equals(method.toString())) {
                anyMatch = true;
                break;
              }
            }
            if (!anyMatch) {
              return error("Assertion method " + method + " not found in DID document.", ctx);
            }
          }

          // get keys from "verificationMethod"
          JsonArray keyVerificationMethod =
              keyStructure.get().asJsonObject().getJsonArray("verificationMethod");
          if (keyVerificationMethod == null) {
            return error(
                "Document doesn't have a list of verification methods at URI: " + uri, ctx);
          }
          Optional<JsonValue> verificationMethodMaybe =
              keyVerificationMethod.stream()
                  .filter(n -> n.asJsonObject().getString("id").equals(method.toString()))
                  .findFirst();
          if (verificationMethodMaybe.isEmpty()) {
            return error("Verification method " + method + " not found in DID document.", ctx);
          }
          JsonObject verificationMethod = verificationMethodMaybe.get().asJsonObject();
          // assuming a Ed25519VerificationKey2020 document
          controller = verificationMethod.getString("controller");
          publicKeyMultibase = verificationMethod.getString("publicKeyMultibase");

        } else {
          return error("Unknown verification method: " + method, ctx);
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
      publicKeyMulticodec = Multibase.decode(publicKeyMultibase);
      if (publicKeyMulticodec[0] != (byte) 0xed || publicKeyMulticodec[1] != (byte) 0x01) {
        return error("Verification method does not contain an Ed25519 public key", ctx);
      }
    } catch (Exception e) {
      return error("Invalid public key: " + e.getMessage(), ctx);
    }

    if (controller != null && credentialHolder.getCredential().getIssuer() != null) {
      if (!controller.equals(credentialHolder.getCredential().getIssuer().toString())) {
        return error(
            "Key controller does not match issuer: " + credentialHolder.getCredential().getIssuer(),
            ctx);
      }
    }

    // Extract the publicKey bytes from the Multicodec
    byte[] publicKey = Multicodec.decode(Codec.Ed25519PublicKey, publicKeyMulticodec);

    // choose verifier
    LdVerifier<?> verifier = getVerifier(proof, publicKey, crd);

    try {
      boolean verify = verifier.verify(credentialHolder.getCredential(), proof);
      if (!verify) {
        // add proof calculations to the report
        Canonicalizer canonicalizer = verifier.getCanonicalizer();
        if (canonicalizer != null) {
          if (canonicalizer instanceof URDNA2015Canonicalizer) {
            URDNA2015Canonicalizer urdna2015Canonicalizer = (URDNA2015Canonicalizer) canonicalizer;
            EmbeddedProofModelGenerator modelGenerator =
                new EmbeddedProofModelGenerator(urdna2015Canonicalizer);
            return error("Embedded proof verification failed.", modelGenerator.getGeneratedObject(), ctx);
          }
        }
        return error("Embedded proof verification failed.", ctx);
      }
    } catch (Exception e) {
      return fatal("Embedded proof verification failed: " + e.getMessage(), ctx);
    }

    return success(ctx);
  }

  private LdVerifier<?> getVerifier(LdProof proof, byte[] publicKey, VerifiableCredential crd) {
    return proof.isType("Ed25519Signature2020")
        ? new Ed25519Signature2020LdVerifier(publicKey)
        : crd.getVersion() == VerifiableCredential.VCVersion.VCDMv1p1
            ? new Ed25519Signature2022LdVerifier(publicKey)
            : new Ed25519Signature2022VCDM20LdVerifier(publicKey);
  }

  private Boolean IsValidPublicKeyMultibase(String publicKeyMultibase) {
    try {
      byte[] publicKeyMulticodec = Multibase.decode(publicKeyMultibase);
      byte[] publicKey = Multicodec.decode(Codec.Ed25519PublicKey, publicKeyMulticodec);
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
