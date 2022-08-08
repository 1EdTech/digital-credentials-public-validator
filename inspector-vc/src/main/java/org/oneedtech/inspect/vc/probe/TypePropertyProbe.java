package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.Credential.Type;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * A Probe that verifies a credential's type property. 
 * @author mgylling
 */
public class TypePropertyProbe extends Probe<JsonNode> {
	private final Credential.Type expected;
	
	public TypePropertyProbe(Credential.Type expected) {
		super(ID);
		this.expected = checkNotNull(expected);
	}
	
	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

		ArrayNode typeNode = (ArrayNode)root.get("type");		
		if(typeNode == null) return fatal("No type property", ctx);
		
		List<String> values = JsonNodeUtil.asStringList(typeNode);
		
		if(!values.contains("VerifiableCredential")) {
			return fatal("The type property does not contain the entry 'VerifiableCredential'", ctx);
		}
		
		if(expected == Credential.Type.OpenBadgeCredential) {
			if(!values.contains("OpenBadgeCredential") && !values.contains("AchievementCredential")) {
				return fatal(
					"The type property does not contain one of 'OpenBadgeCredential' or 'AchievementCredential'",
					ctx);
			}	
		}
		if(expected == Credential.Type.ClrCredential){
			if(!values.contains("ClrCredential")) {
				return fatal(
					"The type property does not contain the entry 'ClrCredential'",
					ctx);
			}	
		} else {
			//TODO implement
			throw new IllegalStateException(); 
		}
		
		return success(ctx);
	}
		
	public static final String ID = TypePropertyProbe.class.getSimpleName(); 
}
