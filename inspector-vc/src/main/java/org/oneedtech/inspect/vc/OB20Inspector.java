package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.oneedtech.inspect.core.Inspector;
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
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A verifier for Open Badges 2.0.
 * @author xaracil
 */
public class OB20Inspector extends Inspector {

	protected OB20Inspector(OB20Inspector.Builder builder) {
		super(builder);
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
				// accumulator.add(new CredentialParseProbe().run(resource, ctx));
				// if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

				// //we expect the above to place a generated object in the context
				// VerifiableCredential ob = ctx.getGeneratedObject(VerifiableCredential.ID);




		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
    }

	public static class Builder extends Inspector.Builder<OB20Inspector.Builder> {
		@SuppressWarnings("unchecked")
		@Override
		public OB20Inspector build() {
			set(Specification.OB20);
			set(ResourceType.OPENBADGE);
			return new OB20Inspector(this);
		}
	}
}
