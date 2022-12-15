package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.core.probe.RunContext.Key.GENERATED_OBJECT_BUILDER;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JACKSON_OBJECTMAPPER;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JSONPATH_EVALUATOR;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JSON_DOCUMENT_LOADER;
import static org.oneedtech.inspect.core.probe.RunContext.Key.JWT_CREDENTIAL_NODE_NAME;
import static org.oneedtech.inspect.core.probe.RunContext.Key.PNG_CREDENTIAL_KEY;
import static org.oneedtech.inspect.core.probe.RunContext.Key.SVG_CREDENTIAL_QNAME;
import static org.oneedtech.inspect.core.probe.RunContext.Key.URI_RESOURCE_FACTORY;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.oneedtech.inspect.core.SubInspector;
import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.Assertion.Type;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;
import org.oneedtech.inspect.vc.probe.AssertionRevocationListProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.VerificationDependenciesProbe;
import org.oneedtech.inspect.vc.resource.UriResourceFactory;

import com.apicatalog.jsonld.loader.DocumentLoader;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * An inspector for EndorsementCredential objects.
 * @author mgylling
 */
public class OB20EndorsementInspector extends VCInspector implements SubInspector {

	private DocumentLoader documentLoader;
	private UriResourceFactory uriResourceFactory;

	protected OB20EndorsementInspector(OB20EndorsementInspector.Builder builder) {
		super(builder);
		this.documentLoader = builder.documentLoader;
		this.uriResourceFactory = builder.uriResourceFactory;
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

		Assertion endorsement = (Assertion) checkNotNull(parentObjects.get(CREDENTIAL_KEY));

		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);

		RunContext ctx = new RunContext.Builder()
				.put(this)
				.put(resource)
				.put(JACKSON_OBJECTMAPPER, mapper)
				.put(JSONPATH_EVALUATOR, jsonPath)
				.put(GENERATED_OBJECT_BUILDER, new Assertion.Builder())
				.put(PNG_CREDENTIAL_KEY, PngParser.Keys.OB20)
				.put(SVG_CREDENTIAL_QNAME, SvgParser.QNames.OB20)
				.put(JSON_DOCUMENT_LOADER, documentLoader)
				.put(JWT_CREDENTIAL_NODE_NAME, Assertion.JWT_NODE_NAME)
				.put(URI_RESOURCE_FACTORY, uriResourceFactory)
				.build();

		parentObjects.entrySet().stream().forEach(entry -> {
			if (!entry.getKey().equals(CREDENTIAL_KEY)) {
				ctx.addGeneratedObject(entry.getValue());
			}
		});

		List<ReportItems> accumulator = new ArrayList<>();
		int probeCount = 0;
        try {

			JsonNode endorsementNode = endorsement.getJson();
			// verification and revocation
			if (endorsement.getCredentialType() == Type.Endorsement) {
				for(Probe<JsonLdGeneratedObject> probe : List.of(new VerificationDependenciesProbe(endorsementNode.get("id").asText(), "claim"),
					new AssertionRevocationListProbe(endorsementNode.get("id").asText(), "claim"))) {
					probeCount++;
					accumulator.add(probe.run(new JsonLdGeneratedObject(endorsementNode.toString()), ctx));
					if(broken(accumulator)) return abort(ctx, accumulator, probeCount);
				}
			}

			// expiration and issuance
			for(Probe<Credential> probe : List.of(
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
	public <R extends Resource> Report run(R resource) {
		throw new IllegalStateException("must use #run(resource, map)");
	}

	public static class Builder extends VCInspector.Builder<OB20EndorsementInspector.Builder> {
		private DocumentLoader documentLoader;
		private UriResourceFactory uriResourceFactory;

		@SuppressWarnings("unchecked")
		@Override
		public OB20EndorsementInspector build() {
			return new OB20EndorsementInspector(this);
		}

		public Builder documentLoader(DocumentLoader documentLoader) {
            this.documentLoader = documentLoader;
            return this;
        }

		public Builder uriResourceFactory(UriResourceFactory uriResourceFactory) {
            this.uriResourceFactory = uriResourceFactory;
            return this;
        }

	}

}
