package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.code.Defensives.*;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;
import static org.oneedtech.inspect.vc.Credential.ProofType.EXTERNAL;
import static org.oneedtech.inspect.vc.payload.PayloadParser.fromJwt;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asNodeList;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.SubInspector;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.code.Defensives;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.Credential.Type;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.ExternalProofProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;

/**
 * A verifier for Open Badges 3.0.
 * @author mgylling
 */
public class OB30Inspector extends VCInspector implements SubInspector {
	protected final List<Probe<Credential>> userProbes;
	
	protected OB30Inspector(OB30Inspector.Builder builder) {	
		super(builder);		
		this.userProbes = ImmutableList.copyOf(builder.probes);		
	}
	
	//https://docs.google.com/document/d/1_imUl2K-5tMib0AUxwA9CWb0Ap1b3qif0sXydih68J0/edit#
	//https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#verificaton-and-validation
	
	/*
	 * This inspector supports both standalone openbadge verification, as well as verification of
	 * AchievementCredentials embedded in e.g. CLR. 
	 * 
	 * When verifying a standalone AchievementCredential, call the run(Resource) method. When verifying
	 * an embedded AchievementCredential, call the run(Resource, Map) method. 
	 */
	
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
				if(broken(accumulator, true)) return abort(ctx, accumulator, probeCount);
				
				//we expect the above to place a generated object in the context				
				Credential ob = ctx.getGeneratedObject(Credential.ID);
				
				//call the subinspector method of this
				Report subReport = this.run(resource, Map.of(Credential.CREDENTIAL_KEY, ob));
				probeCount += subReport.getSummary().getTotalRun();
				accumulator.add(subReport);
				
				//finally, run any user-added probes
				for(Probe<Credential> probe : userProbes) {
					probeCount++;
					accumulator.add(probe.run(ob, ctx));
				}
						
		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}
		
		return new Report(ctx, new ReportItems(accumulator), probeCount); 
	}
	
	@Override
	public Report run(Resource resource, Map<String, GeneratedObject> parentObjects) {
		
		Credential ob = checkNotNull((Credential)parentObjects.get(CREDENTIAL_KEY));
		
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
		
			//context and type properties
			Credential.Type type = Type.OpenBadgeCredential;
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {					
				probeCount++;
				accumulator.add(probe.run(ob.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}
			
			//canonical schema and inline schemata
			SchemaKey schema = ob.getSchemaKey().orElseThrow();
			for(Probe<JsonNode> probe : List.of(new JsonSchemaProbe(schema), new InlineJsonSchemaProbe(schema))) {					
				probeCount++;
				accumulator.add(probe.run(ob.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}
			
			//credentialSubject 
			probeCount++;
			accumulator.add(new CredentialSubjectProbe().run(ob.getJson(), ctx));
			
			//signatures, proofs
			probeCount++;
			if(ob.getProofType() == EXTERNAL){
				//The credential originally contained in a JWT, validate the jwt and external proof.
				accumulator.add(new ExternalProofProbe().run(ob, ctx));
			} else {
				//The credential not contained in a jwt, must have an internal proof.
				accumulator.add(new EmbeddedProofProbe().run(ob, ctx));					
			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
										
			//check refresh service if we are not already refreshed
			probeCount++;
			if(resource.getContext().get(REFRESHED) != TRUE) {
				Optional<String> newID = checkRefreshService(ob, ctx); 											
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
				accumulator.add(probe.run(ob, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}
							
			//embedded endorsements 
			EndorsementInspector endorsementInspector = new EndorsementInspector.Builder().build();	
			
			List<JsonNode> endorsements = asNodeList(ob.getJson(), "$..endorsement", jsonPath);
			for(JsonNode node : endorsements) {
				probeCount++;
				Credential endorsement = new Credential(resource, node);
				accumulator.add(endorsementInspector.run(resource, Map.of(CREDENTIAL_KEY, endorsement)));
			}	
		
			//embedded jwt endorsements 
			endorsements = asNodeList(ob.getJson(), "$..endorsementJwt", jsonPath);
			for(JsonNode node : endorsements) {
				probeCount++;
				String jwt = node.asText();
				JsonNode vcNode = fromJwt(jwt, ctx);
				Credential endorsement = new Credential(resource, vcNode, jwt);
				accumulator.add(endorsementInspector.run(resource, Map.of(CREDENTIAL_KEY, endorsement)));
			}
			
		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}
		
		return new Report(ctx, new ReportItems(accumulator), probeCount); 
		
	}
			
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