package org.oneedtech.inspect.vc.jsonld.probe;

import static java.util.stream.Collectors.joining;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.util.TokenBuffer;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion.VersionFlag;

import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonValue;

/**
 * Probe for extensions in OB 2.0
 * Maps to task "VALIDATE_EXTENSION_NODE" in python implementation
 * @author xaracil
 */
public class ExtensionProbe extends Probe<JsonNode> {
	private final List<String> typesToTest;

	public ExtensionProbe(String entryPath, List<String> typesToTest) {
		super(ID, entryPath, typesToTest.stream().collect(joining()));
		this.typesToTest = typesToTest;
	}

	@Override
	public ReportItems run(JsonNode node, RunContext ctx) throws Exception {
        ReportItems reportItems = new ReportItems();
		DocumentLoader documentLoader = (DocumentLoader) ctx.get(Key.JSON_DOCUMENT_LOADER);
		Set<URI> contexts = null;
		if (documentLoader instanceof CachingDocumentLoader) {
			contexts = new HashSet<>(((CachingDocumentLoader) documentLoader).getContexts());
		} else {
			contexts = Set.of();
		}

		// compact contexts
		URI ob20contextUri = new URI(CONTEXT_URI_STRING);
		ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
		for (URI uri : contexts) {
			if (!uri.equals(ob20contextUri)) {
				JsonLdOptions options = new JsonLdOptions(documentLoader);
                Document contextDocument = documentLoader.loadDocument(uri, new DocumentLoaderOptions());
                JsonNode contextJson = mapper.readTree(contextDocument.getJsonContent().orElseThrow().toString());

				JsonObject compactedContext = JsonLd.compact(uri, "https://w3id.org/openbadges/v2")
					.options(options)
					.get();
				JsonNode context = mapper.readTree(compactedContext.toString());
				List<JsonNode> validations = JsonNodeUtil.asNodeList(context.get("validation"));
				for (JsonNode validation : validations) {
					if (isLdTermInList(validation.get("validatesType"), options)) {
						JsonNode schemaJson = null;
                        URI schemaUri = null;
						try {
                            schemaUri = new URI(validation.get("validationSchema").asText().strip());
							// check schema is valid
							Document schemaDocument = documentLoader.loadDocument(schemaUri, new DocumentLoaderOptions());
							schemaJson = mapper.readTree(schemaDocument.getJsonContent().orElseThrow().toString());
						} catch (Exception e) {
							return fatal("Could not load JSON-schema from URL " + schemaUri, ctx);
						}

						reportItems = new ReportItems(List.of(reportItems, validateSingleExtension(node, uri, contextJson, validation.get("validatesType").asText().strip(), schemaJson, schemaUri, options, ctx)));
					}
				}
			}
		}

		if (reportItems.size() == 0) {
			return error("Could not determine extension type to test", ctx);
		}

		return reportItems;
    }

	private boolean isLdTermInList(JsonNode termNode, JsonLdOptions options) throws JsonLdError {
		JsonDocument jsonDocument = JsonDocument.of(Json.createObjectBuilder()
			.add("@context", CONTEXT_URI_STRING)
			.add("_:term", Json.createObjectBuilder()
				.add("@type", termNode.asText().strip()))
			.add("_:list", Json.createObjectBuilder()
				.add("@type", Json.createArrayBuilder(typesToTest)))
			.build());
		JsonArray expandedDocument = JsonLd.expand(jsonDocument)
			.options(options)
			.get();

		JsonArray list = expandedDocument.getJsonObject(0).getJsonArray("_:list").getJsonObject(0).getJsonArray("@type");
		JsonValue term = expandedDocument.getJsonObject(0).getJsonArray("_:term").getJsonObject(0).getJsonArray("@type").get(0);

		return list.contains(term);
	}

	private ReportItems validateSingleExtension(JsonNode node, URI uri, JsonNode context, String string, JsonNode schemaJson, URI schemaUri, JsonLdOptions options, RunContext ctx) throws JsonGenerationException, JsonMappingException, IOException, JsonLdError {
		ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);

        // validate against JSON schema, using a copy of the node
        TokenBuffer tb = new TokenBuffer(mapper, false);
        mapper.writeValue(tb, node);
        JsonNode auxNode = mapper.readTree(tb.asParser());
        ObjectReader readerForUpdating = mapper.readerForUpdating(auxNode);
        JsonNode merged = readerForUpdating.readValue("{\"@context\": \"" + CONTEXT_URI_STRING + "\"}");

        // combine contexts
        JsonDocument contextsDocument = combineContexts(context);

        JsonObject compactedObject = JsonLd.compact(JsonDocument.of(new StringReader(merged.toString())), contextsDocument)
            .options(options)
            .get();

        // schema probe on compactedObject and schema
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(VersionFlag.V4);
        JsonSchema schema = factory.getSchema(schemaUri, schemaJson);
        return new JsonSchemaProbe(schema).run(mapper.readTree(compactedObject.toString()), ctx);
	}

    private JsonDocument combineContexts(JsonNode context) {
        List<JsonNode> contexts = JsonNodeUtil.asNodeList(context);
        JsonArrayBuilder contextArrayBuilder = Json.createArrayBuilder();
        contextArrayBuilder.add(CONTEXT_URI_STRING); // add OB context to the list
        for (JsonNode contextNode : contexts) {
            if (contextNode.isTextual()) {
                contextArrayBuilder.add(contextNode.asText().strip());
            } else if (contextNode.isObject() && contextNode.hasNonNull("@context")) {
                contextArrayBuilder.add(Json.createReader(new StringReader(contextNode.get("@context").toString())).readObject());

            }
        }

        JsonDocument contextsDocument = JsonDocument.of(Json.createObjectBuilder()
            .add("@context", contextArrayBuilder.build())
            .build());
        return contextsDocument;
    }

	public static final String ID = ExtensionProbe.class.getSimpleName();
	private static final String CONTEXT_URI_STRING = "https://w3id.org/openbadges/v2";
}
