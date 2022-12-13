package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * Verification probe for Open Badges 2.0
 * Maps to "ASSERTION_VERIFICATION_DEPENDENCIES" task in python implementation
 * @author xaracil
 */
public class VerificationDependenciesProbe extends Probe<JsonLdGeneratedObject> {
    private final String assertionId;
    private final String propertyName;

    public VerificationDependenciesProbe(String assertionId) {
        this(assertionId, "badge");
    }

    public VerificationDependenciesProbe(String assertionId, String propertyName) {
        super(ID);
        this.assertionId = assertionId;
        this.propertyName = propertyName;
    }


    @Override
    public ReportItems run(JsonLdGeneratedObject jsonLdGeneratedObject, RunContext ctx) throws Exception {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode jsonNode = (mapper).readTree(jsonLdGeneratedObject.getJson());

        JsonNode verificationNode = jsonNode.get("verification");
        checkNotNull(verificationNode);
        String type = null;
        if (verificationNode.isTextual()) {
            // get verification from graph
            UriResource verificationUriResource = resolveUriResource(ctx, verificationNode.asText().strip());
            JsonLdGeneratedObject verificationObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
                JsonLDCompactionProve.getId(verificationUriResource));
            JsonNode verificationRootNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
                .readTree(verificationObject.getJson());
            type = verificationRootNode.get("type").asText().strip();
        } else {
            type = verificationNode.get("type").asText().strip();
        }

        if ("HostedBadge".equals(type)) {
            // get badge
            UriResource badgeUriResource = resolveUriResource(ctx, getBadgeClaimId(jsonNode));
            JsonLdGeneratedObject badgeObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
                JsonLDCompactionProve.getId(badgeUriResource));
            JsonNode badgeNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
                .readTree(badgeObject.getJson());

            // get issuer from badge
            UriResource issuerUriResource = resolveUriResource(ctx, badgeNode.get("issuer").asText().strip());

            JsonLdGeneratedObject issuerObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
                JsonLDCompactionProve.getId(issuerUriResource));
            JsonNode issuerNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
                .readTree(issuerObject.getJson());

            // verify issuer
            JsonNode verificationPolicy = issuerNode.get("verification");
            try {
                checkNotNull(verificationPolicy);
                if (verificationPolicy.isTextual()) {
                    // get verification node
                    JsonLdGeneratedObject verificationPolicyObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
                        JsonLDCompactionProve.getId(verificationPolicy.asText().strip()));
                        verificationPolicy = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
                            .readTree(verificationPolicyObject.getJson());
                }
            } catch (Throwable t) {
                verificationPolicy = getDefaultVerificationPolicy(issuerNode, mapper);
            }

            // starts with check
            if (verificationPolicy.has("startsWith")) {
                List<String> startsWith = JsonNodeUtil.asStringList(verificationPolicy.get("startsWith"));
                if (!startsWith.stream().anyMatch(assertionId::startsWith)) {
                    return error("Assertion id " + assertionId
                        + "does not start with any permitted values in its issuer's verification policy.", ctx);
                }
            }

            // allowed origins
            JsonNode allowedOriginsNode = verificationPolicy.get("allowedOrigins");
            List<String> allowedOrigins = null;
            String issuerId = issuerNode.get("id").asText().strip();
            if (allowedOriginsNode == null || allowedOriginsNode.isNull()) {
                String defaultAllowedOrigins = getDefaultAllowedOrigins(issuerId);
                if (defaultAllowedOrigins != null) {
                    allowedOrigins = List.of(defaultAllowedOrigins);
                }
            } else {
                allowedOrigins = JsonNodeUtil.asStringList(allowedOriginsNode);
            }

            if (allowedOrigins == null || allowedOrigins.isEmpty() || !issuerId.startsWith("http")) {
                return warning("Issuer " + issuerId + " has no HTTP domain to enforce hosted verification policy against.", ctx);
            }

            if (!allowedOrigins.contains(new URI(assertionId).getAuthority())) {
                return error("Assertion " + assertionId + " not hosted in allowed origins " + allowedOrigins, ctx);
            }
        }
        return success(ctx);
    }

    private JsonNode getDefaultVerificationPolicy(JsonNode issuerNode, ObjectMapper mapper) throws URISyntaxException {
        String issuerId =issuerNode.get("id").asText().strip();

        return mapper.createObjectNode()
            .put("type", "VerificationObject")
            .put("allowedOrigins", getDefaultAllowedOrigins(issuerId))
            .put("verificationProperty", "id");
    }

    private String getDefaultAllowedOrigins(String issuerId) throws URISyntaxException {
        URI issuerUri = new URI(issuerId);
        return issuerUri.getAuthority();
    }

    protected UriResource resolveUriResource(RunContext ctx, String url) throws URISyntaxException {
        URI uri = new URI(url);
        UriResource initialUriResource = new UriResource(uri);
        UriResource uriResource = initialUriResource;

        // check if uri points to a local resource
        if (ctx.get(Key.JSON_DOCUMENT_LOADER) instanceof ConfigurableDocumentLoader) {
            if (ConfigurableDocumentLoader.getDefaultHttpLoader() instanceof CachingDocumentLoader.HttpLoader) {
                URI resolvedUri = ((CachingDocumentLoader.HttpLoader) ConfigurableDocumentLoader.getDefaultHttpLoader()).resolve(uri);
                uriResource = new UriResource(resolvedUri);
            }
        }
        return uriResource;
    }

    /**
     * Return the ID of the node with name propertyName
     * @param jsonNode node
     * @return ID of the node. If node is textual, the text is returned. If node is an object, its "ID" attribute is returned
     */
    protected String getBadgeClaimId(JsonNode jsonNode) {
        JsonNode propertyNode = jsonNode.get(propertyName);
        if (propertyNode.isTextual()) {
            return propertyNode.asText().strip();
        }
        return propertyNode.get("id").asText().strip();
    }


    public static final String ID = VerificationDependenciesProbe.class.getSimpleName();

}
