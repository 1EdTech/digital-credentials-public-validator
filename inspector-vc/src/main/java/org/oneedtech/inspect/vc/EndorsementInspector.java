package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;

import static org.oneedtech.inspect.core.probe.RunContext.Key.*;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;

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
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.vc.Credential.Type;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.ExpirationVerifierProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceVerifierProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.SignatureVerifierProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * An inspector for EndorsementCredential objects. 
 * @author mgylling
 */
public class EndorsementInspector extends VCInspector implements SubInspector {

	protected <B extends VCInspector.Builder<?>> EndorsementInspector(B builder) {
		super(builder);
	}	

	@Override
	public Report run(Resource resource, Map<String, GeneratedObject> parentObjects) {
		/*
		 * The resource param is the top-level credential that embeds the endorsement, we
		 * expect parentObjects to provide a pointer to the JsonNode we should check
		 */
		Credential verifiableCredential = (Credential) parentObjects.get(ENDORSEMENT_KEY);
		
		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		
		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.put(ENDORSEMENT_KEY, verifiableCredential)
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
			
			//type property
			probeCount++;
			accumulator.add(new TypePropertyProbe(Type.ClrCredential).run(crd.getJson(), ctx));
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
		
			//canonical schema and inline schema
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
				//TODO: @Miles Need to fix the issuer, Same as with outer CLR 
				//Swap -> "verificationMethod": "https://example.edu/issuers/565049#z6MkwA1498JfoCS3y4y3zggBDAosQEoCi5gsYH2PMXh1cFWK",
				//To be like -> "verificationMethod": "did:key:z6MkkUD3J14nkYzn46QeuaVSnp7dF85QJKwKvJvfsjx79aXj",
				//...but also work properly which old record seems not be doing...
				
				/*
				accumulator.add(new ProofVerifierProbe().run(crd, ctx));
				*/		
				
			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//check refresh service if we are not already refreshed (check just like in external CLR)
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

			//revocation, expiration and issuance (check just like in external CLR)
			for(Probe<Credential> probe : List.of(new RevocationListProbe(), 
				new ExpirationVerifierProbe(), new IssuanceVerifierProbe())) {					
				probeCount++;
				accumulator.add(probe.run(crd, ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}

		} catch (Exception e) {
			accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
		}

		return new Report(ctx, new ReportItems(accumulator), probeCount);
	}

	@Override
	public <R extends Resource> Report run(R resource) {
		throw new IllegalStateException("must use #run(resource, map)");
	}
	
	public static class Builder extends VCInspector.Builder<EndorsementInspector.Builder> {
		@SuppressWarnings("unchecked")
		@Override
		public EndorsementInspector build() {
			return new EndorsementInspector(this);
		}
	}
	
	public static final String ENDORSEMENT_KEY = "ENDORSEMENT_KEY";
    private static final String REFRESHED = "is.refreshed.credential";

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
}
