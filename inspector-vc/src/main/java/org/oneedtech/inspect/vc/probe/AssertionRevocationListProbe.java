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
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

public class AssertionRevocationListProbe extends Probe<JsonLdGeneratedObject> {
    private final String assertionId;

    public AssertionRevocationListProbe(String assertionId) {
        super(ID);
        this.assertionId = assertionId;
    }

    @Override
    public ReportItems run(JsonLdGeneratedObject jsonLdGeneratedObject, RunContext ctx) throws Exception {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode jsonNode = (mapper).readTree(jsonLdGeneratedObject.getJson());

        // get badge
        UriResource badgeUriResource = resolveUriResource(ctx, jsonNode.get("badge").asText().strip());
        JsonLdGeneratedObject badgeObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProve.getId(badgeUriResource));

        // get issuer from badge
        JsonNode badgeNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(badgeObject.getJson());

        UriResource issuerUriResource = resolveUriResource(ctx, badgeNode.get("issuer").asText().strip());
        JsonLdGeneratedObject issuerObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProve.getId(issuerUriResource));
        JsonNode issuerNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER))
            .readTree(issuerObject.getJson());

        JsonNode revocationListIdNode = issuerNode.get("revocationList");
        if (revocationListIdNode == null) {
            // "Assertion is not revoked. Issuer has no revocation list"
            return success(ctx);
        }

        UriResource revocationListUriResource = resolveUriResource(ctx, revocationListIdNode.asText().strip());
        JsonLdGeneratedObject revocationListObject = (JsonLdGeneratedObject) ctx.getGeneratedObject(
            JsonLDCompactionProve.getId(revocationListUriResource));
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

    public static final String ID = AssertionRevocationListProbe.class.getSimpleName();
}
