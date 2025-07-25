package org.oneedtech.inspect.vc.probe;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

import foundation.identity.jsonld.ConfigurableDocumentLoader;

public class AssertionRevocationListProbe extends Probe<JsonLdGeneratedObject> {
    private final String assertionId;
    private final String propertyName;

    public AssertionRevocationListProbe(String assertionId) {
        this(assertionId, "badge");
    }

    public AssertionRevocationListProbe(String assertionId, String propertyName) {
        super(ID);
        this.assertionId = assertionId;
        this.propertyName = propertyName;
    }

    @Override
    public ReportItems run(JsonLdGeneratedObject jsonLdGeneratedObject, RunContext ctx) throws Exception {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode jsonNode = (mapper).readTree(jsonLdGeneratedObject.getJson());
        UriResourceFactory uriResourceFactory = (UriResourceFactory) ctx.get(Key.URI_RESOURCE_FACTORY);

        // get badge
        UriResource badgeUriResource = uriResourceFactory.of(getBadgeClaimId(jsonNode));
        JsonLdGeneratedObject badgeObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(badgeUriResource));

        // get issuer from badge
        JsonNode badgeNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(badgeObject.getJson());

        UriResource issuerUriResource = uriResourceFactory.of(badgeNode.get("issuer").asText().strip());
        JsonLdGeneratedObject issuerObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(issuerUriResource));
        JsonNode issuerNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(issuerObject.getJson());

        JsonNode revocationListIdNode = issuerNode.get("revocationList");
        if (revocationListIdNode == null) {
            // "Assertion is not revoked. Issuer has no revocation list"
            return success(ctx);
        }

        UriResource revocationListUriResource = uriResourceFactory.of(revocationListIdNode.asText().strip());
        JsonLdGeneratedObject revocationListObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProbe.getId(revocationListUriResource));
        JsonNode revocationListNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(revocationListObject.getJson());

        List<JsonNode> revocationList = JsonNodeUtil.asNodeList(revocationListNode.get("revokedAssertions"));
        List<JsonNode> revokedMatches = revocationList.stream().filter(revocation -> {
            if (revocation.isTextual()) {
                return assertionId.equals(revocation.asText().strip());
            }
            return revocation.get("id") != null && assertionId.equals(revocation.get("id").asText().strip());
        }).collect(Collectors.toList());

        if (revokedMatches.size() > 0) {
            Optional<JsonNode> reasonNode = revokedMatches.stream()
                .map(node -> node.get("revocationReason"))
                .filter(Objects::nonNull)
                .findFirst();
            String reason = reasonNode.isPresent() ? " with reason " + reasonNode.get().asText().strip() : "";
            return error("Assertion " + assertionId + " has been revoked in RevocationList " + revocationListIdNode.asText().strip() + reason, ctx);
        }
        return success(ctx);
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

    public static final String ID = AssertionRevocationListProbe.class.getSimpleName();
}
