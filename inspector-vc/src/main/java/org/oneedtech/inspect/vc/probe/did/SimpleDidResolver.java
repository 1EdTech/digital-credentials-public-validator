package org.oneedtech.inspect.vc.probe.did;

import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonStructure;
import jakarta.json.JsonValue;
import uniresolver.client.ClientUniResolver;
import uniresolver.result.ResolveRepresentationResult;

import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.vc.probe.did.DidResolution.Builder;

public class SimpleDidResolver implements DidResolver {

  private final ClientUniResolver uniResolver;


  public SimpleDidResolver(String uniResolverUrl) {
    this.uniResolver = new ClientUniResolver();
    if (uniResolverUrl != null && !uniResolverUrl.isEmpty()) {
      this.uniResolver.setResolveUri(uniResolverUrl);
    }
  }

  @Override
  public DidResolution resolve(URI did, DocumentLoader documentLoader)
      throws DidResolutionException {
    DidResolution.Builder builder = DidResolution.builder();
    // resolve did using universal did resolver
    if (did.getSchemeSpecificPart().startsWith("key:")) {
      builder.publicKeyMultibase(did.getSchemeSpecificPart().substring("key:".length()));
    } else if (did.getSchemeSpecificPart().startsWith("jwk:")) {
      byte[] decodedJwk = Base64.getUrlDecoder().decode(did.getSchemeSpecificPart().substring("jwk:".length()));
      builder.publicKeyJwk(new String(decodedJwk));
    } else if (did.getSchemeSpecificPart().startsWith("web:")) {
      String methodSpecificId = did.getRawSchemeSpecificPart().substring("web:".length());

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
      URI uri;
      try {
        uri = new URI("https://" + methodSpecificId);
      } catch (URISyntaxException e) {
        throw new DidResolutionException("Invalid URI: " + methodSpecificId);
      }

      // 4. If no path has been specified in the URL, append /.well-known.
      if (uri.getPath() == null || uri.getPath().isEmpty()) {
        uri = uri.resolve("/.well-known");
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
        Document keyDocument = documentLoader.loadDocument(uri, new DocumentLoaderOptions());
        keyStructure = keyDocument.getJsonContent();
      } catch (Exception e) {
        throw new DidResolutionException(
            "Key document not found at "
                + did
                + ". URI: "
                + uri
                + " doesn't return a valid document. Reason: "
                + e.getMessage()
                + " ");
      }
      if (keyStructure.isEmpty()) {
        throw new DidResolutionException(
            "Key document not found at "
                + did
                + ". URI: "
                + uri
                + " doesn't return a valid document. Reason: The document is empty.");
      }

      JsonObject didDocument = keyStructure.get().asJsonObject();
      this.extractFromVerificationMethod(did, didDocument, builder);

    } else {
      try {
        Map<String, Object> resolveOptions = new HashMap<>();
        resolveOptions.put("accept", "application/did+ld+json");

        ResolveRepresentationResult resolveRepresentationResult = uniResolver.resolveRepresentation(did.toString(), resolveOptions);
        if (resolveRepresentationResult.getDidDocumentStream() == null) {
          throw new DidResolutionException("No did document found for did: " + did);
        }

        // read resolveRepresentationResult.getDidDocumentStreamAsString() as JSON Object
        JsonReader jsonReader = Json.createReader(new StringReader(new String(resolveRepresentationResult.getDidDocumentStream(), StandardCharsets.UTF_8)));
        JsonObject didDocument = jsonReader.readObject();

        this.extractFromVerificationMethod(did, didDocument, builder);

      } catch (Exception e) {
        throw new DidResolutionException("Error solvig did: " + did, e);
      }
    }

    return builder.build();
  }

  private void extractFromVerificationMethod(URI did, JsonObject didDocument, Builder builder) throws DidResolutionException {
    JsonArray assertionMethod = didDocument.getJsonArray("assertionMethod");

    if (assertionMethod == null) {
      throw new DidResolutionException(
        "Did Document from " + did + " doesn't have a list of assertion methods");
    } else {
      Boolean anyMatch = false;
      for (int i = 0; i < assertionMethod.size(); i++) {
        String assertionMethodValue = assertionMethod.getString(i);
        if (assertionMethodValue.equals(did.toString())) {
          anyMatch = true;
          break;
        }
      }
      if (!anyMatch) {
        throw new DidResolutionException(
            "Assertion method " + did + " not found in DID document.");
      }
    }

    // get keys from "verificationMethod"
    JsonArray keyVerificationMethod =
        didDocument.getJsonArray("verificationMethod");
    if (keyVerificationMethod == null) {
      throw new DidResolutionException(
        "Did Document from " + did + " doesn't have a list of verification methods");
    }
    Optional<JsonValue> verificationMethodMaybe =
        keyVerificationMethod.stream()
            .filter(n -> n.asJsonObject().getString("id").equals(did.toString()))
            .findFirst();
    if (verificationMethodMaybe.isEmpty()) {
      throw new DidResolutionException(
          "Verification method " + did + " not found in DID document.");
    }
    JsonObject verificationMethod = verificationMethodMaybe.get().asJsonObject();
    // assuming a Ed25519VerificationKey2020 document
    builder
            .controller(verificationMethod.getString("controller"));
    // check JWK
    if (verificationMethod.containsKey("publicKeyJwk"))
      builder.publicKeyJwk(verificationMethod.getJsonObject("publicKeyJwk").toString());
    // check Multibase
    if (verificationMethod.containsKey("publicKeyMultibase"))
      builder.publicKeyMultibase(verificationMethod.getString("publicKeyMultibase"));

  }
}
