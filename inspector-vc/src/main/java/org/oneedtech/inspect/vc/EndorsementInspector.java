package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.core.probe.RunContext.Key.*;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.Map;

import org.oneedtech.inspect.core.SubInspector;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;

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
		Credential endorsement = (Credential) parentObjects.get(ENDORSEMENT_KEY);
		
		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		
		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.put(ENDORSEMENT_KEY, endorsement)
				.build();
		
		System.err.println("TODO" + endorsement.toString());
		
		return new Report(ctx, new ReportItems(), 1); //TODO
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
