package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.vc.VerifiableCredential.Type.*;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;

import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.collect.ImmutableMap;

/**
 * A Probe that verifies a credential's context property.
 *
 * @author mgylling
 */
public class ContextPropertyProbe extends PropertyProbe {
	private final VerifiableCredential.Type type;

	public ContextPropertyProbe(VerifiableCredential.Type type) {
		super(ID, "@context");
		this.type = checkNotNull(type);
		setValidations(this::validate);
	}

	@Override
	protected ReportItems reportForNonExistentProperty(RunContext ctx) {
		return notRun("No @context property", ctx);
	}

	public ReportItems validate(List<String> nodeValues, RunContext ctx) {
		List<String> expected = values.get(values.keySet()
				.stream()
				.filter(s->s.contains(type))
				.findFirst()
				.orElseThrow(()-> new IllegalArgumentException(type.name() + " not recognized")));
		int pos = 0;
		for (String uri : expected) {
			if ((nodeValues.size() < pos + 1) || !nodeValues.get(pos).equals(uri)) {
				return error("missing required @context uri " + uri + " at position " + (pos + 1), ctx);
			}
			pos++;
		}

		return success(ctx);
	}

	private final static Map<Set<VerifiableCredential.Type>, List<String>> values = new ImmutableMap.Builder<Set<VerifiableCredential.Type>, List<String>>()
			.put(Set.of(OpenBadgeCredential, AchievementCredential, EndorsementCredential),
					List.of("https://www.w3.org/2018/credentials/v1",
							//"https://purl.imsglobal.org/spec/ob/v3p0/context.json")) //dev legacy
							"https://purl.imsglobal.org/spec/ob/v3p0/context.json"))
			.put(Set.of(ClrCredential),
					List.of("https://www.w3.org/2018/credentials/v1",
//							"https://dc.imsglobal.org/draft/clr/v2p0/context", //dev legacy
//							"https://purl.imsglobal.org/spec/ob/v3p0/context.json")) //dev legacy
							"https://purl.imsglobal.org/spec/clr/v2p0/context.json",
							"https://purl.imsglobal.org/spec/ob/v3p0/context.json"))

			.build();

	public static final String ID = ContextPropertyProbe.class.getSimpleName();
}
