package org.oneedtech.inspect.clr;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;
import static org.oneedtech.inspect.vc.VCInspector.InjectionKeys.*;
import static org.oneedtech.inspect.vc.VerifiableCredential.REFRESH_SERVICE_MIME_TYPES;
import static org.oneedtech.inspect.vc.VerifiableCredential.ProofType.EXTERNAL;
import static org.oneedtech.inspect.vc.payload.PayloadParser.fromJwt;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asNodeList;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.clr.probe.ClrSubjectProbe;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.StringResource;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.EndorsementInspector;
import org.oneedtech.inspect.vc.OB30Inspector;
import org.oneedtech.inspect.vc.VCInspector;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.VerifiableCredential.Type;
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
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
import org.velocitynetwork.contracts.VelocityNetworkDidResolver;
import org.velocitynetwork.contracts.VelocityNetworkMetadataRegistryFacade;
import org.velocitynetwork.contracts.VelocityNetworkMetadataRegistryFacadeImpl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.io.CharSource;

/**
 * A verifier for Comprehensive Learner Record 2.0.
 * @author mlyon
 */
public class CLR20Inspector extends VCInspector {
	protected final List<Probe<VerifiableCredential>> userProbes;
	protected final String didResolutionUrl;
	protected final Map<String, Object> vnConfig;

	protected CLR20Inspector(CLR20Inspector.Builder builder) {
		super(builder);
		this.userProbes = ImmutableList.copyOf(builder.getProbes());
		Optional<Object> didResolutionServiceUrl = builder.getInjected(DID_RESOLUTION_SERVICE_URL);
		this.didResolutionUrl = didResolutionServiceUrl.isPresent() ? didResolutionServiceUrl.get().toString(): null;
		Optional<Map<String, Object>> vnConfig = builder.getInjected(VNF_CONFIG);
		this.vnConfig = vnConfig.orElseGet(HashMap::new);
	}

    @Override
	public Report run(Resource resource) {
		super.check(resource);	//TODO because URIs, this should be a fetch and cache

		if(getBehavior(RESET_CACHES_ON_RUN) == TRUE) {
			JsonSchemaCache.reset();
			CachingDocumentLoader.reset();
		}

		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		VelocityNetworkDidResolver velocityNetworkDidResolver = null;

		if(!this.vnConfig.isEmpty()) {
			// registry impl
			VelocityNetworkMetadataRegistryFacade velocityNetworkMetadataRegistryFacade = null;
			if (this.vnConfig.containsKey(VNF_REGISTRY)) {
				velocityNetworkMetadataRegistryFacade = (VelocityNetworkMetadataRegistryFacade) this.vnConfig.get(VNF_REGISTRY);
			} else {
				velocityNetworkMetadataRegistryFacade =
					new VelocityNetworkMetadataRegistryFacadeImpl(
						this.vnConfig.getOrDefault(VNF_RPC_URL, "").toString(),
						this.vnConfig.getOrDefault(VNF_PRIVATE_KEY, "").toString(),
						this.vnConfig.getOrDefault(VNF_CONTACT_ADDRESS, "").toString(),
						this.vnConfig.getOrDefault(VNF_RPC_OAUTH_ENDPOINT, null).toString(),
						this.vnConfig.getOrDefault(VNF_RPC_OAUTH_CLIENT_ID, null).toString(),
						this.vnConfig.getOrDefault(VNF_RPC_OAUTH_CLIENT_SECRET, null).toString()
					);
			}
			velocityNetworkDidResolver = new VelocityNetworkDidResolver(velocityNetworkMetadataRegistryFacade, this.vnConfig.getOrDefault(VNF_BURNER_DID, "").toString());
		}
      	DidResolver didResolver = new SimpleDidResolver(this.didResolutionUrl, velocityNetworkDidResolver);

		VerifiableCredential.Builder credentialBuilder = new VerifiableCredential.Builder();
		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(Key.JACKSON_OBJECTMAPPER, mapper)
				.put(Key.JSONPATH_EVALUATOR, jsonPath)
				.put(Key.GENERATED_OBJECT_BUILDER, credentialBuilder)
				.put(Key.PNG_CREDENTIAL_KEY, PngParser.Keys.CLR20)
				.put(Key.SVG_CREDENTIAL_QNAME, SvgParser.QNames.CLR20)
				.put(Key.JWT_CREDENTIAL_NODE_NAME, VerifiableCredential.JWT_NODE_NAME)
				.put(RunContextKey.DID_RESOLVER, didResolver)
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;

        try {
            //detect type (png, svg, json, jwt) and extract json data
            probeCount++;
            accumulator.add(new CredentialParseProbe().run(resource, ctx));
            if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

            //we expect the above to place a generated object in the context
			VerifiableCredential clr = ctx.getGeneratedObject(VerifiableCredential.ID);

			//context and type properties
			VerifiableCredential.Type type = Type.ClrCredential;
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
				probeCount++;
				accumulator.add(probe.run(clr.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//canonical schema
			SchemaKey schema = clr.getSchemaKey().orElseThrow();
			probeCount++;
			accumulator.add(new JsonSchemasProbe(schema).run(clr, ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			// inline schema
			probeCount++;
			accumulator.add(new InlineJsonSchemaProbe(schema).run(clr.getJson(), ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//credentialSubject
			probeCount++;
			accumulator.add(new ClrSubjectProbe("ClrSubject").run(clr.getJson(), ctx));

			//signatures, proofs
			probeCount++;
			if(clr.getProofType() == EXTERNAL){
				//The credential originally contained in a JWT, validate the jwt and external proof.
				accumulator.add(new ExternalProofProbe().run(clr, ctx));
			} else {
				accumulator.add(new EmbeddedProofProbe().run(clr, ctx));
			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//check refresh service if we are not already refreshed
			probeCount++;
			if(resource.getContext().get(REFRESHED) != TRUE) {
				Optional<String> newID = checkRefreshService(clr, ctx);
				if(newID.isPresent()) {
					// If the refresh is not successful, continue the verification process using the original OpenBadgeCredential.
					UriResource uriResource = new UriResource(new URI(newID.get()), null, REFRESH_SERVICE_MIME_TYPES);
					if (uriResource.exists()) {
						accumulator.add(this.run(uriResource.setContext(new ResourceContext(REFRESHED, TRUE))));
					}
				}
			}

			//revocation, expiration and issuance
			for(Probe<Credential> probe : List.of(new RevocationListProbe(),
					new ExpirationProbe(), new IssuanceProbe())) {
				probeCount++;
				accumulator.add(probe.run(clr, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

			//embedded endorsements
			EndorsementInspector.Builder endorsementInspectorBuilder = new EndorsementInspector.Builder();
			if (didResolutionUrl != null) {
				endorsementInspectorBuilder = endorsementInspectorBuilder.inject(DID_RESOLUTION_SERVICE_URL, didResolutionUrl);
			}
			EndorsementInspector endorsementInspector = endorsementInspectorBuilder.build();

			List<JsonNode> endorsements = asNodeList(clr.getJson(), "$..endorsement", jsonPath);
			for(JsonNode node : endorsements) {
				probeCount++;
				VerifiableCredential endorsement = credentialBuilder.resource(resource).jsonData(node).build();
				accumulator.add(endorsementInspector.run(resource, Map.of(CREDENTIAL_KEY, endorsement)));
			}

			//embedded jwt endorsements
			endorsements = asNodeList(clr.getJson(), "$..endorsementJwt", jsonPath);
			for(JsonNode node : endorsements) {
				probeCount++;
				String jwt = node.asText();
				JsonNode vcNode = fromJwt(jwt, ctx);
				VerifiableCredential endorsement = credentialBuilder.resource(resource).jsonData(vcNode).jwt(jwt).build();
				accumulator.add(endorsementInspector.run(resource, Map.of(CREDENTIAL_KEY, endorsement)));
			}

			//embedded subject credentials
			String path = "$.credentialSubject.verifiableCredential";
			List<JsonNode> vcs = asNodeList(clr.getJson(), path, jsonPath);
			OB30Inspector.Builder obInspectorBuilder = new OB30Inspector.Builder();
			if (didResolutionUrl != null) {
				obInspectorBuilder = obInspectorBuilder.inject(DID_RESOLUTION_SERVICE_URL, this.didResolutionUrl);
			}
			OB30Inspector obInspector = obInspectorBuilder.build();

			for (int i = 0; i < vcs.size(); i++) {
				JsonNode node = vcs.get(i);
				String systemId = new StringBuilder().append(resource.getID()).append('/')
						.append(path).append('[').append(i).append(']').toString();
				Resource vcr = new StringResource(CharSource.wrap(node.toString()), systemId, ResourceType.JSON);
				VerifiableCredential vc = credentialBuilder.resource(vcr).jsonData(node).build();

				if(vc.getCredentialType() == Type.AchievementCredential) {
					Report report = obInspector.run(vcr, Map.of(CREDENTIAL_KEY, vc));
					probeCount += report.getSummary().getTotalRun();
					accumulator.add(report);
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				} else {
					//TODO run generic proof check using iron?
					//or issue warning that not checked?
				}
			}

			//finally, run any user-added probes
			for(Probe<VerifiableCredential> probe : userProbes) {
				probeCount++;
				accumulator.add(probe.run(clr, ctx));
			}


		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

        return new Report(ctx, new ReportItems(accumulator), probeCount);
    }



	public static class Builder extends VCInspector.Builder<CLR20Inspector.Builder> {
		@SuppressWarnings("unchecked")
		@Override
		public CLR20Inspector build() {
			set(Specification.CLR20);
			set(ResourceType.CLR);
			return new CLR20Inspector(this);
		}
	}
}
