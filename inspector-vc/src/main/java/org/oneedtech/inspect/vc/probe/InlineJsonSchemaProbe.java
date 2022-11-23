package org.oneedtech.inspect.vc.probe;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.vc.VerifiableCredential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Detect inline schemas in a credential and run them.
 * @author mgylling
 */
public class InlineJsonSchemaProbe extends Probe<JsonNode> {
	private static final Set<String> types = Set.of("1EdTechJsonSchemaValidator2019");
	private SchemaKey skip;

	public InlineJsonSchemaProbe() {
		super(ID);
	}

	public InlineJsonSchemaProbe(SchemaKey skip) {
		super(ID);
		this.skip = skip;
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {
		List<ReportItems> accumulator = new ArrayList<>();
		Set<String> ioErrors = new HashSet<>();

		//note - we don't get deep nested ones in e.g. EndorsementCredential
		JsonNode credentialSchemaNode = root.get("credentialSchema");
		if(credentialSchemaNode == null) return success(ctx);

		ArrayNode schemas = (ArrayNode)	credentialSchemaNode; //TODO guard this cast

		for(JsonNode schemaNode : schemas) {
			JsonNode typeNode = schemaNode.get("type");
			if(typeNode == null || !types.contains(typeNode.asText())) continue;
			JsonNode idNode = schemaNode.get("id");
			if(idNode == null) continue;
			String id = idNode.asText().strip();
			if(ioErrors.contains(id)) continue;
			if(equals(skip, id)) continue;
			try {
				accumulator.add(new JsonSchemaProbe(id).run(root, ctx));
			} catch (Exception e) {
				if(!ioErrors.contains(id)) {
					ioErrors.add(id);
					accumulator.add(error("Could not read schema resource " + id, ctx));
				}
			}
		}

		return new ReportItems(accumulator);
	}

	private boolean equals(SchemaKey key, String id) {
		if(key == null) return false;
		return key.getCanonicalURI().equals(id);
	}

	public static final String ID = InlineJsonSchemaProbe.class.getSimpleName();
}
