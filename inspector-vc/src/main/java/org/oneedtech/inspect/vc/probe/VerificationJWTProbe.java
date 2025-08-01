package org.oneedtech.inspect.vc.probe;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProbe;
import org.oneedtech.inspect.vc.resource.UriResourceFactory;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * Recipient Verification probe for Open Badges 2.0
 * Maps to "VERIFY_JWS" task in python implementation
 * @author xaracil
 */
public class VerificationJWTProbe extends Probe<JsonLdGeneratedObject> {
    final String jwt;

    public VerificationJWTProbe(String jwt) {
        super(ID);
        this.jwt = jwt;
    }

    @Override
    public ReportItems run(JsonLdGeneratedObject assertion, RunContext ctx) throws Exception {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode assertionNode = (mapper).readTree(assertion.getJson());
        UriResourceFactory uriResourceFactory = (UriResourceFactory) ctx.get(Key.URI_RESOURCE_FACTORY);

        // get badge from assertion
        UriResource badgeUriResource = uriResourceFactory.of(assertionNode.get("badge").asText().strip());
        JsonLdGeneratedObject badgeObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(badgeUriResource));
        JsonNode badgeNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(badgeObject.getJson());

        // get issuer from badge
        UriResource issuerUriResource = uriResourceFactory.of(badgeNode.get("issuer").asText().strip());

        JsonLdGeneratedObject issuerObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(issuerUriResource));
        JsonNode issuerNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(issuerObject.getJson());

        // get verification from assertion
        JsonNode creatorIdNode = assertionNode.get("verification").get("creator");
        String creatorId = null;
        if (creatorIdNode != null) {
            creatorId = creatorIdNode.asText().strip();
        } else {
            // If not present, verifiers will check public key(s) declared in the referenced issuer Profile.
            creatorId = issuerNode.get("publicKeyPem").asText().strip();
        }

        // get creator from id
        UriResource creatorUriResource = uriResourceFactory.of(creatorId);
        JsonLdGeneratedObject creatorObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(creatorUriResource));
        JsonNode creatorNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(creatorObject.getJson());

        // verify key ownership
        String keyId = creatorNode.get("id").asText().strip();
        List<String> issuerKeys = JsonNodeUtil.asStringList(issuerNode.get("publicKey"));
        if (!issuerKeys.contains(keyId)) {
            return error("Assertion signed by a key " + keyId + " other than those authorized by issuer profile", ctx);
        }
        String publicKeyPem = creatorNode.get("publicKeyPem").asText().strip();

        // verify signature
        publicKeyPem = publicKeyPem.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replace("-----END PUBLIC KEY-----", "");
        publicKeyPem = publicKeyPem.replace("\n", "");

        byte[] encodedPb = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(encodedPb);
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpecPb);

        JWSObject jwsObject = JWSObject.parse(jwt);
        JWSVerifier verifier = new RSASSAVerifier(publicKey);
        try {
            if (!jwsObject.verify(verifier)) {
                return error("Signature for node " + assertionNode.get("id") + " failed verification ", ctx);
            }
        } catch (JOSEException e) {
            return fatal("Signature for node " + assertionNode.get("id") + " failed verification " + e.getLocalizedMessage(), ctx);
        }
        return success(ctx);
    }

    private static final List<String> allowedTypes = List.of("id", "email", "url", "telephone");
    public static final String ID = VerificationJWTProbe.class.getSimpleName();

}
