package org.oneedtech.inspect.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.probe.RunContext.Key.*;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

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
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.util.resource.context.ResourceContext;
import org.oneedtech.inspect.vc.Credential.Type;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.ExpirationVerifierProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceVerifierProbe;
import org.oneedtech.inspect.vc.probe.ProofVerifierProbe;
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
		 * expect parentObjects to provide a pointer to the JsonNode we should check.
		 * 
		 * The parent inspector is responsible to decode away possible jwt-ness, so that
		 * what we get here is a verbatim json node. 
		 * 
		 */
		
		Credential endorsement = (Credential) checkNotNull(parentObjects.get(ENDORSEMENT_KEY));
				
		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		
		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.build();

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;
        try {
								
			//context and type properties
			Credential.Type type = Type.EndorsementCredential;
			for(Probe<JsonNode> probe : List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {					
				probeCount++;
				accumulator.add(probe.run(endorsement.getJson(), ctx));
				if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
			}
			
			//inline schema (parent inspector has already validated against canonical)
			accumulator.add(new InlineJsonSchemaProbe().run(endorsement.getJson(), ctx));
									
			//signatures, proofs
			probeCount++;
			if(endorsement.getJwt().isPresent()){
				//The credential originally contained in a JWT, validate the jwt and external proof.
				accumulator.add(new SignatureVerifierProbe().run(endorsement, ctx));
			} else {
				//The credential not contained in a jwt, must have an internal proof.
				accumulator.add(new ProofVerifierProbe().run(endorsement, ctx));		
				
			}
			if(broken(accumulator)) return abort(ctx, accumulator, probeCount);

			//check refresh service if we are not already refreshed (check just like in external CLR)
			probeCount++;
			if(resource.getContext().get(REFRESHED) != TRUE) {
				Optional<String> newID = checkRefreshService(endorsement, ctx); 											
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
				accumulator.add(probe.run(endorsement, ctx));
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
   
}
