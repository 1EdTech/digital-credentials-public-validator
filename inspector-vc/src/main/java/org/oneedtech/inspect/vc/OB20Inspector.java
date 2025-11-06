package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static java.util.stream.Collectors.toList;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asNodeList;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.util.code.Tuple;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.Assertion.Type;
import org.oneedtech.inspect.vc.Credential.CredentialEnum;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.ExtensionProbe;
import org.oneedtech.inspect.vc.jsonld.probe.GraphFetcherProbe;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProbe;
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
import org.oneedtech.inspect.vc.resource.UriResourceFactory;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A verifier for Open Badges 2.0.
 * @author xaracil
 */
public class OB20Inspector extends VCInspector {

	protected <B extends VCInspector.Builder<?>> OB20Inspector(B builder) {
		super(builder);
	}

	/* (non-Javadoc)
	 * @see org.oneedtech.inspect.core.Inspector#run(org.oneedtech.inspect.util.resource.Resource)
	 */
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
		UriResourceFactory uriResourceFactory = getUriResourceFactory(documentLoader);

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
				.put(Key.JWT_CREDENTIAL_ALLOW_WHOLE_PAYLOAD, Assertion.JWT_ALLOW_WHOLE_PAYLOAD)
				.put(Key.URI_RESOURCE_FACTORY, uriResourceFactory)
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
			accumulator.add(new JsonLDCompactionProbe(assertion.getCredentialType().getContextUris().get(0)).run(assertion, ctx));
			if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

			// validate JSON LD
			JsonLdGeneratedObject jsonLdGeneratedObject = ctx.getGeneratedObject(JsonLDCompactionProbe.getId(assertion));
			accumulator.add(new JsonLDValidationProbe().run(jsonLdGeneratedObject.getJson(), ctx));
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
				accumulator.add(ValidationPropertyProbeFactory.of(assertion.getCredentialType().toString(), validation).run(assertionNode, ctx));
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

			// expiration and issuance
			for(Probe<Credential> probe : List.of(
					new ExpirationProbe(), new IssuanceProbe())) {
				probeCount++;
				accumulator.add(probe.run(assertion, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			// get all json-ld generated objects for both extension and endorsements validation
			List<JsonNode> jsonLdGeneratedObjects = ctx.getGeneratedObjects().values().stream()
				.filter(generatedObject -> generatedObject instanceof JsonLdGeneratedObject)
				.map(obj -> {

					try {
						return mapper.readTree(((JsonLdGeneratedObject) obj).getJson());
					} catch (JsonProcessingException e) {
						throw new IllegalArgumentException("Couldn't not parse " + obj.getId() + ": contains invalid JSON");
					}
				})
				.collect(toList());

			// validate extensions
			List<Tuple<ExtensionProbe, JsonNode>> extensionProbeTuples = jsonLdGeneratedObjects.stream()
				.flatMap(node -> getExtensionProbes(node, "id").stream())
				.collect(toList());
			for (Tuple<ExtensionProbe, JsonNode> extensionProbeTuple : extensionProbeTuples) {
				probeCount++;
				accumulator.add(extensionProbeTuple.t1.run(extensionProbeTuple.t2, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			// Embedded endorsements. Pass document loader because it has already cached documents, and it has localdomains for testing
			OB20EndorsementInspector endorsementInspector = new OB20EndorsementInspector.Builder()
				.documentLoader(documentLoader)
				.uriResourceFactory(uriResourceFactory)
				.build();

			// get endorsements for all JSON_LD objects in the graph
			List<JsonNode> endorsements = jsonLdGeneratedObjects.stream().flatMap(node -> {
				// return endorsement node, filtering out the on inside @context
				return asNodeList(node, "$..endorsement", jsonPath).stream().filter(endorsementNode -> !endorsementNode.isObject());
			})
			.collect(toList());

			for(JsonNode node : endorsements) {
				probeCount++;
				// get endorsement json from context
				UriResource uriResource = uriResourceFactory.of(node.asText());
				JsonLdGeneratedObject resolved = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProbe.getId(uriResource));
				if (resolved == null) {
					throw new IllegalArgumentException("endorsement " + node.toString() + " not found in graph");
				}

				Assertion endorsement = new Assertion.Builder().resource(resource).jsonData(mapper.readTree(resolved.getJson())).build();
				// pass graph to subinspector
				Map<String, GeneratedObject> parentObjects = new HashMap<>(ctx.getGeneratedObjects());
				parentObjects.put(CREDENTIAL_KEY, endorsement);
				accumulator.add(endorsementInspector.run(resource, parentObjects));
			}

		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
    }

	public static class Builder extends VCInspector.Builder<OB20Inspector.Builder> {

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
