package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.Type.OpenBadgeCredential;
import static org.oneedtech.inspect.vc.EndorsementInspector.ENDORSEMENT_KEY;
import static org.oneedtech.inspect.vc.payload.PayloadParser.fromJwt;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asNodeList;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.ExpirationVerifierProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceVerifierProbe;
import org.oneedtech.inspect.vc.probe.ProofVerifierProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.SignatureVerifierProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;

/**
 * A verifier for Open Badges 3.0.
 * @author mgylling
 */
public class OB30Inspector extends VCInspector {
	protected final List<Probe<Credential>> userProbes;
	
	protected OB30Inspector(OB30Inspector.Builder builder) {			
		super(builder);		
		this.userProbes = ImmutableList.copyOf(builder.probes);
	}
	
	//https://docs.google.com/document/d/1_imUl2K-5tMib0AUxwA9CWb0Ap1b3qif0sXydih68J0/edit#
	//https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#verificaton-and-validation
	
	@Override
	public Report run(Resource resource) {		
		super.check(resource);	//TODO because URIs, this should be a fetch and cache
		
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
				.build();		
						
		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;
		
		try {					
				//detect type (png, svg, json, jwt) and extract json data
				probeCount++;
				accumulator.add(new CredentialParseProbe().run(resource, ctx));				
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				
				//we expect the above to place a generated object in the context				
				Credential crd = ctx.getGeneratedObject(Credential.ID);
				
				//TODO check context IRIs? the schema doesnt do this 
				
				//TODO new check: that subject @id or IdentityObject is available (at least one is the req)
				
				//type property
				probeCount++;
				accumulator.add(new TypePropertyProbe(OpenBadgeCredential).run(crd.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
												
				//canonical schema and inline schemata
				SchemaKey schema = crd.getSchemaKey().orElseThrow();
				for(Probe<JsonNode> probe : List.of(new JsonSchemaProbe(schema), new InlineJsonSchemaProbe(schema))) {					
					probeCount++;
					accumulator.add(probe.run(crd.getJson(), ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
				
				//signatures, proofs
				probeCount++;
				if(crd.getJwt().isPresent()){
					//The credential originally contained in a JWT, validate the jwt and external proof.
					accumulator.add(new SignatureVerifierProbe().run(crd, ctx));
				} else {
					//The credential not contained in a jwt, must have an internal proof.
					accumulator.add(new ProofVerifierProbe().run(crd, ctx));					
				}
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
											
				//check refresh service if we are not already refreshed
				probeCount++;
				if(resource.getContext().get(REFRESHED) != TRUE) {
					Optional<String> newID = checkRefreshService(crd, ctx); 											
					if(newID.isPresent()) {		
						//TODO resource.type
						return this.run(
							new UriResource(new URI(newID.get()))
								.setContext(new ResourceContext(REFRESHED, TRUE)));
					}
				}
						
				//revocation, expiration and issuance
				for(Probe<Credential> probe : List.of(new RevocationListProbe(), 
						new ExpirationVerifierProbe(), new IssuanceVerifierProbe())) {					
					probeCount++;
					accumulator.add(probe.run(crd, ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
								
				//embedded endorsements 
				EndorsementInspector endorsementInspector = new EndorsementInspector.Builder().build();	
				
				List<JsonNode> endorsements = asNodeList(crd.getJson(), "$..endorsement", jsonPath);								
				for(JsonNode node : endorsements) {
					probeCount++;
					Credential endorsement = new Credential(resource, node);
					accumulator.add(endorsementInspector.run(resource, Map.of(ENDORSEMENT_KEY, endorsement)));
				}	
			
				//embedded jwt endorsements 
				endorsements = asNodeList(crd.getJson(), "$..endorsementJwt", jsonPath);				
				for(JsonNode node : endorsements) {
					probeCount++;
					String jwt = node.asText();
					JsonNode vcNode = fromJwt(jwt, ctx);
					Credential endorsement = new Credential(resource, vcNode, jwt);
					accumulator.add(endorsementInspector.run(resource, Map.of(ENDORSEMENT_KEY, endorsement)));
				}
											
				//finally, run any user-added probes
				for(Probe<Credential> probe : userProbes) {
					probeCount++;
					accumulator.add(probe.run(crd, ctx));
				}
						
		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}
		
		return new Report(ctx, new ReportItems(accumulator), probeCount); 
	}
	
	/**
	 * If the AchievementCredential or EndorsementCredential has a “refreshService” property and the type of the 
	 * RefreshService object is “1EdTechCredentialRefresh”, you should fetch the refreshed credential from the URL 
	 * provided, then start the verification process over using the response as input. If the request fails, 
	 * the credential is invalid.
	 */
	private Optional<String> checkRefreshService(Credential crd, RunContext ctx) {
		JsonNode refreshServiceNode = crd.getJson().get("refreshService");		
		if(refreshServiceNode != null) {
			JsonNode serviceTypeNode = refreshServiceNode.get("type");
			if(serviceTypeNode != null && serviceTypeNode.asText().equals("1EdTechCredentialRefresh")) {
				JsonNode serviceURINode = refreshServiceNode.get("id");
				if(serviceURINode != null) {
					return Optional.of(serviceURINode.asText());
				}
			}	
		}				
		return Optional.empty();
	}

	private static final String REFRESHED = "is.refreshed.credential";
		
	public static class Builder extends VCInspector.Builder<OB30Inspector.Builder> {
		@SuppressWarnings("unchecked")
		@Override
		public OB30Inspector build() {
			set(Specification.OB30);
			set(ResourceType.OPENBADGE);
			return new OB30Inspector(this);
		}
	}
	
}