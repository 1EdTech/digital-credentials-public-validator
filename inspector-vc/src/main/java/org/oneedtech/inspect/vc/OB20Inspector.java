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
import org.oneedtech.inspect.vc.jsonld.probe.GraphFetcherProbe;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDValidationProbe;
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;
import org.oneedtech.inspect.vc.probe.AssertionRevocationListProbe;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.probe.VerificationDependenciesProbe;
import org.oneedtech.inspect.vc.probe.VerificationJWTProbe;
import org.oneedtech.inspect.vc.probe.validation.ValidationPropertyProbeFactory;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.jsonld.loader.DocumentLoader;
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
		DocumentLoader documentLoader = getDocumentLoader();

		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(Key.JACKSON_OBJECTMAPPER, mapper)
				.put(Key.JSONPATH_EVALUATOR, jsonPath)
				.put(Key.GENERATED_OBJECT_BUILDER, new Assertion.Builder())
				.put(Key.PNG_CREDENTIAL_KEY, PngParser.Keys.OB20)
				.put(Key.SVG_CREDENTIAL_QNAME, SvgParser.QNames.OB20)
				.put(Key.JSON_DOCUMENT_LOADER, documentLoader)
				.put(Key.JWT_CREDENTIAL_NODE_NAME, Assertion.JWT_NODE_NAME)
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;

		try {
			//detect type (png, svg, json, jwt) and extract json data
			probeCount++;
			accumulator.add(new CredentialParseProbe().run(resource, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// we expect the above to place a generated object in the context
			Assertion assertion = ctx.getGeneratedObject(resource.getID());

			//context and type properties
			CredentialEnum type = assertion.getCredentialType();
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
				probeCount++;
				accumulator.add(probe.run(assertion.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			// let's compact
			accumulator.add(new JsonLDCompactionProve(assertion.getCredentialType().getContextUris().get(0)).run(assertion, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// validate JSON LD
			JsonLdGeneratedObject jsonLdGeneratedObject = ctx.getGeneratedObject(JsonLDCompactionProve.getId(assertion));
			accumulator.add(new JsonLDValidationProbe(jsonLdGeneratedObject).run(assertion, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// validation the Open Badge, from the compacted form
			JsonNode assertionNode = mapper.readTree(jsonLdGeneratedObject.getJson());

			// mount the graph, flattening embedded resources
			probeCount++;
			accumulator.add(new GraphFetcherProbe(assertion).run(assertionNode, ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			// perform validations
			List<Validation> validations = assertion.getValidations();
			for (Validation validation : validations) {
				probeCount++;
				accumulator.add(ValidationPropertyProbeFactory.of(validation).run(assertionNode, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			// expiration and issuance
			for(Probe<Credential> probe : List.of(
					new ExpirationProbe(), new IssuanceProbe())) {
				probeCount++;
				accumulator.add(probe.run(assertion, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			// verification and revocation
			if (assertion.getCredentialType() == Type.Assertion) {
				for(Probe<JsonLdGeneratedObject> probe : List.of(new VerificationDependenciesProbe(assertionNode.get("id").asText()),
					new AssertionRevocationListProbe(assertionNode.get("id").asText()))) {
					probeCount++;
					accumulator.add(probe.run(jsonLdGeneratedObject, ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}

				// JWS verification
				if (assertion.getJwt().isPresent()) {
					probeCount++;
					accumulator.add(new VerificationJWTProbe(assertion.getJwt().get()).run(jsonLdGeneratedObject, ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
			}


		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
    }

	protected DocumentLoader getDocumentLoader() {
		return new CachingDocumentLoader();
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
