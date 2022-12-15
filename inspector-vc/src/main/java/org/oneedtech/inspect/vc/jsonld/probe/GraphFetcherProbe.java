package org.oneedtech.inspect.vc.jsonld.probe;

import static org.oneedtech.inspect.vc.Assertion.ValueType.DATA_URI_OR_URL;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.Assertion;
import org.oneedtech.inspect.vc.Assertion.Type;
import org.oneedtech.inspect.vc.Assertion.ValueType;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.resource.UriResourceFactory;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;
import org.oneedtech.inspect.vc.util.PrimitiveValueValidator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.io.Resources;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * Probe for fetching all elements in the graph for Open Badges 2.0 validation
 * Contains the fetch part of "VALIDATE_TYPE_PROPERTY" task in python implementation, as well as the "FLATTEN_EMBEDDED_RESOURCE" task
 * @author xaracil
 */
public class GraphFetcherProbe extends Probe<JsonNode> {
    private final Assertion assertion;

    public GraphFetcherProbe(Assertion assertion) {
        super(ID);
        this.assertion = assertion;
    }

    @Override
    public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
        ReportItems result = new ReportItems();

        // get validations of IDs and fetch
        List<Validation> validations = assertion.getValidations().stream()
            .filter(validation -> validation.getType() == ValueType.ID && validation.isFetch())
            .collect(Collectors.toList());

        for (Validation validation : validations) {
            JsonNode node = root.get(validation.getName());

            if (node == null) {
                // if node is null, continue. ValidationPropertyProbe will check if the field was required
                continue;
            }

            // flatten embeded resource
            if (validation.isAllowFlattenEmbeddedResource()) {
                if (!node.isTextual()) {
                    if (!node.isObject()) {
                        return error("Property " + validation.getName() + " referenced from " + assertion.getJson().toString() + " is not a JSON object or string as expected", ctx);
                    }

                    JsonNode idNode = node.get("id");
                    if (idNode == null) {
                        // add a new node to the graph
                        UUID newId = UUID.randomUUID();
                        JsonNode merged = createNewJson(ctx, "{\"id\": \"_:" + newId + "\"}");
                        ctx.addGeneratedObject(new JsonLdGeneratedObject(JsonLDCompactionProve.getId(newId.toString()), merged.toString()));

                        // update existing node with new id
                        updateNode(validation, idNode, ctx);

                        return warning("Node id missing at " + node.toString() + ". A blank node ID has been assigned", ctx);
                    } else if (!idNode.isTextual() || !PrimitiveValueValidator.validateIri(idNode)) {
                        return error("Embedded JSON object at " + node.asText() + " has no proper assigned id.", ctx);
                    } else if (assertion.getCredentialType() == Type.Assertion && !PrimitiveValueValidator.validateUrl(idNode)) {
                        if (!isUrn(idNode)) {
                            logger.info("ID format for " + idNode.toString() + " at " + assertion.getCredentialType() + " not in an expected HTTP or URN:UUID scheme");
                        }

                        // add a new node to the graph
                        JsonNode merged = createNewJson(ctx, node);
                        ctx.addGeneratedObject(new JsonLdGeneratedObject(JsonLDCompactionProve.getId(idNode.asText().strip()), merged.toString()));

                        // update existing node with new id
                        updateNode(validation, idNode, ctx);

                    } else {

                        // update existing node with new id
                        updateNode(validation, idNode, ctx);

                        // fetch node and add it to the graph
                        result = fetchNode(ctx, result, idNode);
                    }
                }
            }

            List<JsonNode> nodeList = JsonNodeUtil.asNodeList(node);
            for (JsonNode childNode : nodeList) {
                if (shouldFetch(childNode, validation)) {
                    // get node from context
                    result = fetchNode(ctx, result, childNode);
                }
            }

        }
        return success(ctx);
    }

    private ReportItems fetchNode(RunContext ctx, ReportItems result, JsonNode idNode)
            throws URISyntaxException, Exception, JsonProcessingException, JsonMappingException {
        System.out.println("fetchNode " + idNode.asText().strip());
        UriResource uriResource = ((UriResourceFactory) ctx.get(Key.URI_RESOURCE_FACTORY)).of(idNode.asText().strip());
        JsonLdGeneratedObject resolved = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(uriResource));
        if (resolved == null) {
            System.out.println("parsing and loading " + idNode.asText().strip());
            result = new ReportItems(List.of(result, new CredentialParseProbe().run(uriResource, ctx)));
            if (!result.contains(Outcome.FATAL, Outcome.EXCEPTION)) {
                Assertion fetchedAssertion = (Assertion) ctx.getGeneratedObject(uriResource.getID());

                // compact ld
                result = new ReportItems(List.of(result, new JsonLDCompactionProve(fetchedAssertion.getCredentialType().getContextUris().get(0)).run(fetchedAssertion, ctx)));
                if (!result.contains(Outcome.FATAL, Outcome.EXCEPTION)) {
                    JsonLdGeneratedObject fetched = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(fetchedAssertion));
                    JsonNode fetchedNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER)).readTree(fetched.getJson());

                    // recursive call
                    result = new ReportItems(List.of(result, new GraphFetcherProbe(fetchedAssertion).run(fetchedNode, ctx)));
                }
            }
        }
        return result;
    }

    /**
     * Tells if we have to fetch the id. We have to fecth if:
     * - the node is not a complex node
     * - not (validation allow data-uri but the node is not of this type)
     * - not (validation doesn't allow data-uri but the node is not an IRI)
     * @param node
     * @param validation
     * @return
     */
    private boolean shouldFetch(JsonNode node, Validation validation) {
        return !node.isObject() &&
            (!validation.isAllowDataUri() || DATA_URI_OR_URL.getValidationFunction().apply(node)) &&
            (validation.isAllowDataUri() || ValueType.IRI.getValidationFunction().apply(node));
    }

    private void updateNode(Validation validation, JsonNode idNode, RunContext ctx) throws IOException {
        JsonLdGeneratedObject jsonLdGeneratedObject = ctx.getGeneratedObject(JsonLDCompactionProve.getId(assertion));
        JsonNode merged = createNewJson(ctx, jsonLdGeneratedObject.getJson(), "{\"" + validation.getName() + "\": \"" + idNode.asText().strip() + "\"}");
        jsonLdGeneratedObject.setJson(merged.toString());

    }

    private JsonNode createNewJson(RunContext ctx, JsonNode node) throws IOException {
        return createNewJson(ctx, Resources.getResource("contexts/ob-v2p0.json"), node.toString());
    }

    private JsonNode createNewJson(RunContext ctx, String additional) throws IOException {
        return createNewJson(ctx, Resources.getResource("contexts/ob-v2p0.json"), additional);
    }

    private JsonNode createNewJson(RunContext ctx, URL original, String additional) throws IOException {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode newNode = mapper.readTree(original);
        ObjectReader readerForUpdating = mapper.readerForUpdating(newNode);
        JsonNode merged = readerForUpdating.readValue(additional);
        return merged;
    }

    private JsonNode createNewJson(RunContext ctx, String original, String updating) throws IOException {
        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
        JsonNode source = mapper.readTree(original);
        ObjectReader readerForUpdating = mapper.readerForUpdating(source);
        JsonNode merged = readerForUpdating.readValue(updating);
        return merged;
    }


    private boolean isUrn(JsonNode idNode) {
        final Pattern pattern = Pattern.compile(URN_REGEX, Pattern.CASE_INSENSITIVE);
        final Matcher matcher = pattern.matcher(idNode.asText());
        return matcher.matches();
    }

    public static final String ID = GraphFetcherProbe.class.getSimpleName();
    public static final String URN_REGEX = "^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'";
    protected final static Logger logger = LogManager.getLogger(GraphFetcherProbe.class);
}
