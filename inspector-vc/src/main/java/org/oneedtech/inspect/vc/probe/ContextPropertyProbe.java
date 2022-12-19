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
				if ((nodeValues.size() < pos + 1) || !nodeValues.get(pos).equals(uri)) {
					return error("missing required @context uri " + uri + " at position " + (pos + 1), ctx);
				}
				pos++;
			}
		}

		return success(ctx);
	}

	public static final String ID = ContextPropertyProbe.class.getSimpleName();
}
