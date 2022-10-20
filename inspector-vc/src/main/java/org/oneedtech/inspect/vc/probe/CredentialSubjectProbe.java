package org.oneedtech.inspect.vc.probe;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * A Probe that checks credential subject specifics not capturable by schemata.
 * 
 * @author mgylling
 */
public class CredentialSubjectProbe extends Probe<JsonNode> {
	
	public CredentialSubjectProbe() {
		super(ID);
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

		JsonNode subject = root.get("credentialSubject");
		if(subject == null) return notRun("no credentialSubject node found", ctx); //error reported by schema

		/*
		 * Check that we have either .id or .identifier populated 
		 */
		JsonNode id = root.get("id");
		if (id != null && id.textValue().strip().length() > 0) return success(ctx);
				
		JsonNode identifier = root.get("identifier");		
		if(identifier != null && identifier instanceof ArrayNode 
				&& ((ArrayNode)identifier).size() > 0) return success(ctx);
					
		return error("no id in credentialSubject", ctx);
				
	}

	public static final String ID = CredentialSubjectProbe.class.getSimpleName();
}
