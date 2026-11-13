package org.oneedtech.inspect.vc.probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Detect inline schemas in a credential and run them.
 * @author mgylling
 */
public class InlineJsonSchemaProbe extends Probe<JsonNode> {
	private static final Set<String> types = Set.of("1EdTechJsonSchemaValidator2019");
	private static final Map<String, SchemaKey> localSchemas = new ConcurrentHashMap<>();
	private SchemaKey skip;

	public InlineJsonSchemaProbe() {
		super(ID, TITLE);
	}

	public InlineJsonSchemaProbe(SchemaKey skip) {
		super(ID, TITLE);
		this.skip = skip;
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
		List<ReportItems> accumulator = new ArrayList<>();
		Set<String> ioErrors = new HashSet<>();

		//note - we don't get deep nested ones in e.g. EndorsementCredential
		JsonNode credentialSchemaNode = root.get("credentialSchema");
		if(credentialSchemaNode == null) return success("No credentialSchema node found", ctx);

		List<JsonNode> schemas = JsonNodeUtil.asNodeList(credentialSchemaNode);

		for(JsonNode schemaNode : schemas) {
			JsonNode typeNode = schemaNode.get("type");
			if(typeNode == null || !types.contains(typeNode.asText())) continue;
			JsonNode idNode = schemaNode.get("id");
			if(idNode == null) continue;
			String id = idNode.asText().strip();
			if(ioErrors.contains(id)) continue;
			if(equals(skip, id)) continue;
			try {
				SchemaKey local = localSchemas.get(id);
				JsonSchemaProbe probe = local != null ? new JsonSchemaProbe(local) : new JsonSchemaProbe(id);
				accumulator.add(probe.run(root, ctx));
			} catch (Exception e) {
				if(!ioErrors.contains(id)) {
					ioErrors.add(id);
					accumulator.add(error("Could not read schema resource " + id, ctx));
				}
			}
		}

		return new ReportItems(accumulator);
	}

	/**
	 * Register a locally bundled schema, so that inline references to its canonical URI are
	 * validated against the bundled copy instead of being fetched over the network.
	 */
	public static void registerLocalSchema(SchemaKey key) {
		localSchemas.put(key.getCanonicalURI(), key);
	}

	private boolean equals(SchemaKey key, String id) {
		if(key == null) return false;
		return key.getCanonicalURI().equals(id);
	}

	public static final String ID = InlineJsonSchemaProbe.class.getSimpleName();
	public static final String TITLE = "Inline JSON Schema Validation";
}
