package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.EndorsementInspector.ENDORSEMENT_KEY;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.getEndorsements;
import static com.google.common.base.Strings.isNullOrEmpty;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonArrayProbe;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.probe.json.JsonPredicates.JsonPredicateProbeParams;
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
import org.oneedtech.inspect.vc.probe.CredentialTypeProbe;
import org.oneedtech.inspect.vc.probe.ExpirationVerifierProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceVerifierProbe;
import org.oneedtech.inspect.vc.probe.Predicates;
import org.oneedtech.inspect.vc.probe.ProofVerifierProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.SignatureVerifierProbe;

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
		super.check(resource);		
		
		if(getBehavior(RESET_CACHES_ON_RUN) == TRUE) JsonSchemaCache.reset();
				
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
				//TODO turn into a loop once stable
			
				//detect type (png, svg, json, jwt) and extract json data
				probeCount++;
				accumulator.add(new CredentialTypeProbe().run(resource, ctx));				
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				
				//we expect the above to place a generated object in the context				
				Credential crd = ctx.getGeneratedObject(Credential.ID);
				
				//validate the value of the type property
				probeCount++;
				accumulator.add(new JsonArrayProbe(vcType).run(crd.asJson(), ctx));
				probeCount++;	
				accumulator.add(new JsonArrayProbe(obType).run(crd.asJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);		
				
				//validate against the canonical schema	 	
				SchemaKey canonical = crd.getSchemaKey().orElseThrow();
				probeCount++;
				accumulator.add(new JsonSchemaProbe(canonical).run(crd.asJson(), ctx));
				
				//validate against any inline schemas 	
				probeCount++;
				accumulator.add(new InlineJsonSchemaProbe().run(crd, ctx));
				
				//If this credential was originally contained in a JWT we must validate the jwt and external proof.
				if(!isNullOrEmpty(crd.getJwt())){
					probeCount++;
					accumulator.add(new SignatureVerifierProbe().run(crd, ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
				
				//verify proofs TODO @Miles
				//If this credential was not contained in a jwt it must have an internal proof.
				if(isNullOrEmpty(crd.getJwt())){
					probeCount++;
					accumulator.add(new ProofVerifierProbe().run(crd, ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
			
				//check refresh service if we are not already refreshed
				probeCount++;
				if(resource.getContext().get(REFRESHED) != TRUE) {					
					Optional<String> newID = checkRefreshService(crd, ctx); //TODO fail = invalid
					if(newID.isPresent()) {						
						return this.run(
							new UriResource(new URI(newID.get()))
								.setContext(new ResourceContext(REFRESHED, TRUE)));
					}
				}
				
				//check revocation status
				probeCount++;
				accumulator.add(new RevocationListProbe().run(crd, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				
				//check expiration
				probeCount++;
				accumulator.add(new ExpirationVerifierProbe().run(crd, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				
				//check issuance
				probeCount++;
				accumulator.add(new IssuanceVerifierProbe().run(crd, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				
				//embedded endorsements 
				List<JsonNode> endorsements = getEndorsements(crd.asJson(), jsonPath);
				if(endorsements.size() > 0) {
					EndorsementInspector subInspector = new EndorsementInspector.Builder().build();	
					for(JsonNode endorsementNode : endorsements) {
						probeCount++;
						//TODO: @Markus @Miles, need to refactor to detect as this can be an internal or external proof credential.
						//This will LIKELY come from two distinct sources in which case we would detect the type by property name.
						//Third param to constructor: Compact JWT -> add third param after decoding.  Internal Proof, null jwt string.
						//Credential endorsement = new Credential(resource, endorsementNode);
						//accumulator.add(subInspector.run(resource, Map.of(ENDORSEMENT_KEY, endorsement)));
					}
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
		//TODO
		return Optional.empty();
	}

	private static final String REFRESHED = "is.refreshed.credential";
	
	private static final JsonPredicateProbeParams obType = JsonPredicateProbeParams.of(
			"$.type", Predicates.OB30.TypeProperty.value, Predicates.OB30.TypeProperty.msg, Outcome.FATAL);
	
	private static final JsonPredicateProbeParams vcType = JsonPredicateProbeParams.of(
			"$.type", Predicates.VC.TypeProperty.value, Predicates.VC.TypeProperty.msg, Outcome.FATAL);
	
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