package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;
import java.util.Map;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.ImmutableMap;

/**
 * A Probe that verifies a credential's context property.
 * 
 * @author mgylling
 */
public class ContextPropertyProbe extends Probe<JsonNode> {
	private final Credential.Type type;

	public ContextPropertyProbe(Credential.Type type) {
		super(ID);
		this.type = checkNotNull(type);
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

		ArrayNode contextNode = (ArrayNode) root.get("@context");
		if (contextNode == null) {
			return fatal("No @context property", ctx);	
		}
			
		List<String> expected = values.get(type);
		if(expected == null) {
			return fatal(type.name() + " not recognized", ctx);
		}
		
		List<String> given = JsonNodeUtil.asStringList(contextNode);
		int pos = 0;
		for(String uri : expected) {
			if((given.size() < pos+1) || !given.get(pos).equals(uri)) {
				return error("missing required @context uri " + uri + " at position " + (pos+1), ctx);	
			}
			pos++;
		}
				
		return success(ctx);
	}

	private final static Map<Credential.Type, List<String>> values = new ImmutableMap.Builder<Credential.Type, List<String>>()
	           .put(Credential.Type.OpenBadgeCredential, 
	        		   List.of("https://www.w3.org/2018/credentials/v1", 
	        				   "https://imsglobal.github.io/openbadges-specification/context.json")) //TODO will change (https://purl.imsglobal.org/spec/ob/v3p0/context/ob_v3p0.jsonld)
	           .build();
	
	public static final String ID = ContextPropertyProbe.class.getSimpleName();
}
