package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.ArrayList;
import java.util.List;

import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.Assertion.Type;
import org.oneedtech.inspect.vc.Credential.CredentialEnum;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDValidationProbe;
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A verifier for Open Badges 2.0.
 * @author xaracil
 */
public class OB20Inspector extends Inspector {

	protected OB20Inspector(OB20Inspector.Builder builder) {
		super(builder);
	}

	protected Report abort(RunContext ctx, List<ReportItems> accumulator, int probeCount) {
		return new Report(ctx, new ReportItems(accumulator), probeCount);
	}

	protected boolean broken(List<ReportItems> accumulator) {
		return broken(accumulator, false);
	}

	protected boolean broken(List<ReportItems> accumulator, boolean force) {
		if(!force && getBehavior(Inspector.Behavior.VALIDATOR_FAIL_FAST) == Boolean.FALSE) {
			return false;
		}
		for(ReportItems items : accumulator) {
			if(items.contains(Outcome.FATAL, Outcome.EXCEPTION)) return true;
		}
		return false;
	}


	@Override
	public Report run(Resource resource) {
		super.check(resource);

		if(getBehavior(RESET_CACHES_ON_RUN) == TRUE) {
			JsonSchemaCache.reset();
			CachingDocumentLoader.reset();
		}

        ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);

		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(Key.JACKSON_OBJECTMAPPER, mapper)
				.put(Key.JSONPATH_EVALUATOR, jsonPath)
				.put(Key.GENERATED_OBJECT_BUILDER, new Assertion.Builder())
				.put(Key.PNG_CREDENTIAL_KEY, PngParser.Keys.OB20)
				.put(Key.SVG_CREDENTIAL_QNAME, SvgParser.QNames.OB20)
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;

		try {
			//detect type (png, svg, json, jwt) and extract json data
			probeCount++;
			accumulator.add(new CredentialParseProbe().run(resource, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// we expect the above to place a generated object in the context
			Assertion assertion = ctx.getGeneratedObject(Assertion.ID);

			// let's compact
			accumulator.add(getCompactionProbe(assertion).run(assertion, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// validate JSON LD
			JsonLdGeneratedObject jsonLdGeneratedObject = ctx.getGeneratedObject(JsonLdGeneratedObject.ID);
			accumulator.add(new JsonLDValidationProbe(jsonLdGeneratedObject).run(assertion, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			//context and type properties
			CredentialEnum type = assertion.getCredentialType();
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
				probeCount++;
				accumulator.add(probe.run(assertion.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//canonical schema and inline schemata
			// SchemaKey schema = assertion.getSchemaKey().orElseThrow();
			// for(Probe<JsonNode> probe : List.of(new JsonSchemaProbe(schema), new InlineJsonSchemaProbe(schema))) {
			// 	probeCount++;
			// 	accumulator.add(probe.run(assertion.getJson(), ctx));
			// 	if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			// }
		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
    }

	protected JsonLDCompactionProve getCompactionProbe(Assertion assertion) {
		return new JsonLDCompactionProve(assertion.getCredentialType().getContextUris().get(0));
	}

	public static class Builder extends Inspector.Builder<OB20Inspector.Builder> {

		public Builder() {
			super();
			// don't allow local redirections by default
			super.behaviors.put(Behavior.ALLOW_LOCAL_REDIRECTION, false);
		}

		@SuppressWarnings("unchecked")
		@Override
		public OB20Inspector build() {
			set(Specification.OB20);
			set(ResourceType.OPENBADGE);
			return new OB20Inspector(this);
		}
	}

	public static class Behavior extends Inspector.Behavior {
		/**
		 * Whether to support local redirection of uris
		 */
		public static final String ALLOW_LOCAL_REDIRECTION = "ALLOW_LOCAL_REDIRECTION";
	}

}
