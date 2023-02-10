package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential.CredentialEnum;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A Probe that verifies a credential's context property.
 *
 * @author mgylling
 */
public class ContextPropertyProbe extends StringValuePropertyProbe {
	private final CredentialEnum type;

	public ContextPropertyProbe(CredentialEnum type) {
		super(ID, type.toString(), "@context");
		this.type = checkNotNull(type);
		setValueValidations(this::validate);
	}

	@Override
	protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
		return notRun("No @context property", ctx);
	}

	public ReportItems validate(List<String> nodeValues, RunContext ctx) {
		if (!nodeValues.isEmpty()) { // empty context uri node: inline context
			List<String> contextUris = type.getContextUris();
			checkNotNull(contextUris);

			int pos = 0;
			for (String uri : contextUris) {
				if ((nodeValues.size() < pos + 1) || !contains(uri, nodeValues.get(pos))) {
					return error("missing required @context uri " + uri + " at position " + (pos + 1), ctx);
				}
				pos++;
			}
		}

		return success(ctx);
	}

	private boolean contains(String uri, String nodeValue) {
		// check equal case
		if (nodeValue.equals(uri)) {
			return true;
		}
		// check aliases
		if (type.getContextAliases().containsKey(uri)) {
			if (type.getContextAliases().get(uri).stream().anyMatch(alias -> nodeValue.equals(alias))) {
				return true;
			}
		}
		// check versioning
		if (type.getContextVersionPatterns().containsKey(uri)) {
			if (type.getContextVersionPatterns().get(uri).stream().anyMatch(version -> nodeValue.matches(version))) {
				return true;
			}
		}
		return false;
	}

	public static final String ID = ContextPropertyProbe.class.getSimpleName();
}
