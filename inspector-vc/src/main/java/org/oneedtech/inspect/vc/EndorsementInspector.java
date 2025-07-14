package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL;
import static org.oneedtech.inspect.core.probe.RunContext.Key.GENERATED_OBJECT_BUILDER;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JSONPATH_EVALUATOR;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;
import static org.oneedtech.inspect.vc.VerifiableCredential.REFRESH_SERVICE_MIME_TYPES;
import static org.oneedtech.inspect.vc.VerifiableCredential.ProofType.EXTERNAL;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.SubInspector;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.vc.VerifiableCredential.Type;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.ExternalProofProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.JsonSchemasProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.RunContextKey;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.probe.did.DidResolver;
import org.oneedtech.inspect.vc.probe.did.SimpleDidResolver;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;

/**
 * An inspector for EndorsementCredential objects.
 * @author mgylling
 */
public class EndorsementInspector extends VCInspector implements SubInspector {

	protected final List<Probe<VerifiableCredential>> userProbes;
	protected final String didResolutionUrl;

	protected EndorsementInspector(EndorsementInspector.Builder builder) {
		super(builder);
		this.userProbes = ImmutableList.copyOf(builder.probes);
		Optional<Object> didResolutionServiceUrl = builder.getInjected(DID_RESOLUTION_SERVICE_URL);
		this.didResolutionUrl = didResolutionServiceUrl.isPresent() ? didResolutionServiceUrl.get().toString(): null;
	}

	@Override
	public Report run(Resource resource, Map<String, GeneratedObject> parentObjects) {

		/*
		 * The resource param is the top-level credential that embeds the endorsement, we
		 * expect parentObjects to provide a pointer to the JsonNode we should check.
		 *
		 * The parent inspector is responsible to decode away possible jwt-ness, so that
		 * what we get here is a verbatim json node.
		 *
		 */

		VerifiableCredential endorsement = (VerifiableCredential) checkNotNull(parentObjects.get(CREDENTIAL_KEY));

		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		DidResolver didResolver = new SimpleDidResolver(this.didResolutionUrl, null);

		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.put(RunContextKey.DID_RESOLVER, didResolver)
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;
        try {

			//context and type properties
			VerifiableCredential.Type type = Type.EndorsementCredential;
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
				probeCount++;
				accumulator.add(probe.run(endorsement.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//inline schema (parent inspector has already validated against canonical)
			accumulator.add(new InlineJsonSchemaProbe().run(endorsement.getJson(), ctx));

			//signatures, proofs
			probeCount++;
			if(endorsement.getProofType() == EXTERNAL){
				//The credential originally contained in a JWT, validate the jwt and external proof.
				accumulator.add(new ExternalProofProbe().run(endorsement, ctx));
			} else {
				//The credential not contained in a jwt, must have an internal proof.
				accumulator.add(new EmbeddedProofProbe().run(endorsement, ctx));

			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//check refresh service if we are not already refreshed (check just like in external CLR)
			probeCount++;
			if(resource.getContext().get(REFRESHED) != TRUE) {
				Optional<String> newID = checkRefreshService(endorsement, ctx);
				if(newID.isPresent()) {
					// If the refresh is not successful, continue the verification process using the original EndorsementCredential.
					UriResource uriResource = new UriResource(new URI(newID.get()), null, REFRESH_SERVICE_MIME_TYPES);
					if (uriResource.exists()) {
						return this.run(uriResource.setContext(new ResourceContext(REFRESHED, TRUE)));
					}
				}
			}

			//revocation, expiration and issuance
			for(Probe<Credential> probe : List.of(new RevocationListProbe(),
				new ExpirationProbe(), new IssuanceProbe())) {
				probeCount++;
				accumulator.add(probe.run(endorsement, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
	}

	@Override
	public Report run(Resource resource) {
		super.check(resource);

		if (getBehavior(RESET_CACHES_ON_RUN) == TRUE) {
			JsonSchemaCache.reset();
			CachingDocumentLoader.reset();
		}

		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);

		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.put(GENERATED_OBJECT_BUILDER, new VerifiableCredential.Builder())
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;

		try {
			// detect type (png, svg, json, jwt) and extract json data
			probeCount++;
			accumulator.add(new CredentialParseProbe().run(resource, ctx));
			if (broken(accumulator, true))
				return abort(ctx, accumulator, probeCount);

			// we expect the above to place a generated object in the context
			VerifiableCredential endorsement = ctx.getGeneratedObject(VerifiableCredential.ID);

			//context and type properties
			VerifiableCredential.Type type = Type.EndorsementCredential;
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
				probeCount++;
				accumulator.add(probe.run(endorsement.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//canonical schema
			SchemaKey schema = endorsement.getSchemaKey().orElseThrow();
			probeCount++;
			accumulator.add(new JsonSchemasProbe(schema).run(endorsement, ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			// inline schema
			probeCount++;
			accumulator.add(new InlineJsonSchemaProbe(schema).run(endorsement.getJson(), ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//credentialSubject
			probeCount++;
			accumulator.add(new CredentialSubjectProbe("EndorsementSubject").run(endorsement.getJson(), ctx));

			//signatures, proofs
			probeCount++;
			if(endorsement.getProofType() == EXTERNAL){
				//The credential originally contained in a JWT, validate the jwt and external proof.
				accumulator.add(new ExternalProofProbe().run(endorsement, ctx));
			} else {
				accumulator.add(new EmbeddedProofProbe().run(endorsement, ctx));
			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//check refresh service if we are not already refreshed
			probeCount++;
			if(resource.getContext().get(REFRESHED) != TRUE) {
				Optional<String> newID = checkRefreshService(endorsement, ctx);
				if(newID.isPresent()) {
					return this.run(
						new UriResource(new URI(newID.get()))
							.setContext(new ResourceContext(REFRESHED, TRUE)));
				}
			}

			//revocation, expiration and issuance
			for(Probe<Credential> probe : List.of(new RevocationListProbe(),
					new ExpirationProbe(), new IssuanceProbe())) {
				probeCount++;
				accumulator.add(probe.run(endorsement, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//finally, run any user-added probes
			for(Probe<VerifiableCredential> probe : userProbes) {
				probeCount++;
				accumulator.add(probe.run(endorsement, ctx));
			}

		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
	}

	public static class Builder extends VCInspector.Builder<EndorsementInspector.Builder> {
		@SuppressWarnings("unchecked")
		@Override
		public EndorsementInspector build() {
			return new EndorsementInspector(this);
		}
	}

}
