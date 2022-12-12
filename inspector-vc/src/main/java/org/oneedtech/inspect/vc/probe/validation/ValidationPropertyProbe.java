package org.oneedtech.inspect.vc.probe.validation;

import static org.oneedtech.inspect.vc.Assertion.ValueType.DATA_URI;
import static org.oneedtech.inspect.vc.Assertion.ValueType.DATA_URI_OR_URL;
import static org.oneedtech.inspect.vc.Assertion.ValueType.URL;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.core.report.ReportUtil;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.Assertion.ValueType;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.probe.PropertyProbe;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * Validator for properties of type other than ValueType.RDF_TYPE in Open Badges 2.0 types
 * Maps to "VALIDATE_TYPE_PROPERTY" task in python implementation
 * @author xaracil
 */
public class ValidationPropertyProbe extends PropertyProbe {
    protected final Validation validation;
    protected final boolean fullValidate; // TODO: fullValidate

    public ValidationPropertyProbe(Validation validation) {
        this(ID, validation, true);
    }

    public ValidationPropertyProbe(String id, Validation validation) {
        this(id, validation, true);
    }

    public ValidationPropertyProbe(Validation validation, boolean fullValidate) {
        this(ID, validation, fullValidate);
    }

    public ValidationPropertyProbe(String id, Validation validation, boolean fullValidate) {
        super(id + "<" + validation.getName() + ">", validation.getName());
        this.validation = validation;
        this.fullValidate = fullValidate;
        setValidations(this::validate);
    }

    @Override
    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        if (fullValidate && validation.isRequired()) {
            return error("Required property " + validation.getName() + " not present in " + node.toPrettyString(), ctx);
        } else {
            // optional property or not doing full validation
            return success(ctx);
        }
    }

    /**
     *  Validates presence and data type of a single property that is
     * expected to be one of the Open Badges Primitive data types or an ID.
     * @param node node to check data type
     * @param ctx associated run context
     * @return validation result
     */
    protected ReportItems validate(JsonNode node, RunContext ctx) {
        ReportItems result = new ReportItems();

        // required property
        if (validation.isRequired()) {
            if (node.isObject()) {
                if (!node.fieldNames().hasNext()) {
                   return error("Required property " + validation.getName() + " value " + node.toString() + " is not acceptable", ctx);
                }
            } else {
                List<String> values = JsonNodeUtil.asStringList(node);
                if (values == null ||values.isEmpty()) {
                    return error("Required property " + validation.getName() + " value " + values + " is not acceptable", ctx);
                }
            }
        }

        List<JsonNode> nodeList = JsonNodeUtil.asNodeList(node);
        // many property
        if (!validation.isMany()) {
            if (nodeList.size() > 1) {
                return error("Property " + validation.getName() + "has more than the single allowed value.", ctx);
            }
        }

        try {
            if (validation.getType() != ValueType.ID) {
                Function<JsonNode, Boolean> validationFunction = validation.getType().getValidationFunction();
                for (JsonNode childNode : nodeList) {
                    Boolean valid = validationFunction.apply(childNode);
                    if (!valid) {
                        return error(validation.getType() + " property " + validation.getName() + " value " + childNode.toString() + " not valid", ctx);
                    }
                }
            } else {
                // pre-requisites
                result = new ReportItems(List.of(result, validatePrerequisites(node, ctx)));
                if (result.contains(Outcome.ERROR, Outcome.EXCEPTION)) {
                    return result;
                }
                for (JsonNode childNode : nodeList) {
                    if (childNode.isObject()) {
                        result = new ReportItems(List.of(result, validateExpectedTypes(childNode, ctx)));
                        continue;
                    } else if (validation.isAllowDataUri() && !DATA_URI_OR_URL.getValidationFunction().apply(childNode)){
                        return error("ID-type property " + validation.getName() + " had value `" + childNode.toString() + "` that isn't URI or DATA URI in " + node.toString(), ctx);
                    } else if (!validation.isAllowDataUri() && !ValueType.IRI.getValidationFunction().apply(childNode)) {
                        return error("ID-type property " + validation.getName() + " had value `" + childNode.toString() + "` where another scheme may have been expected " + node.toString(), ctx);
                    }

                    // get node from context
                    UriResource uriResource = resolveUriResource(ctx, childNode.asText());
                    JsonLdGeneratedObject resolved = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(uriResource));
                    if (resolved == null) {
                        if (validation.isAllowRemoteUrl() && URL.getValidationFunction().apply(childNode)) {
                            continue;
                        }

                        if (validation.isAllowDataUri() && DATA_URI.getValidationFunction().apply(childNode)) {
                            continue;
                        }
                        return error("Node " + node.toString() + " has " + validation.getName() +" property value `" + childNode.toString() + "` that appears not to be in URI format", ctx);
                    } else {
                        ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
                        JsonNode resolvedNode = mapper.readTree(resolved.getJson());

                        // validate expected node class
                        result = new ReportItems(List.of(result, validateExpectedTypes(resolvedNode, ctx)));
                    }
                }
            }
        } catch (Throwable t) {
            return fatal(t.getMessage(), ctx);
        }

        return result.size() > 0 ? result : success(ctx);
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

    private ReportItems validatePrerequisites(JsonNode node, RunContext ctx) {
        List<ReportItems> results = validation.getPrerequisites().stream()
        .map(v -> ValidationPropertyProbeFactory.of(v, validation.isFullValidate()))
        .map(probe -> {
            try {
                return probe.run(node, ctx);
            } catch (Exception e) {
                return ReportUtil.onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, null, e);
            }
        })
        .collect(Collectors.toList());

        return new ReportItems(results);
    }

    private ReportItems validateExpectedTypes(JsonNode node, RunContext ctx) {
        List<ReportItems> results = validation.getExpectedTypes().stream()
        .flatMap(type -> type.getValidations().stream())
        .map(v -> ValidationPropertyProbeFactory.of(v, validation.isFullValidate()))
        .map(probe -> {
            try {
                return probe.run(node, ctx);
            } catch (Exception e) {
                return ReportUtil.onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, null, e);
            }
        })
        .collect(Collectors.toList());
        return new ReportItems(results);
    }

    public static final String ID = ValidationPropertyProbe.class.getSimpleName();
}
