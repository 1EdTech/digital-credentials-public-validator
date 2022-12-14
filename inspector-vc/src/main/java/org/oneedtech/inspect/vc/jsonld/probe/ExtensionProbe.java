package org.oneedtech.inspect.vc.jsonld.probe;

import java.net.URI;
import java.util.Set;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.fasterxml.jackson.databind.JsonNode;

public class ExtensionProbe extends Probe<JsonNode> {

	@Override
	public ReportItems run(JsonNode node, RunContext ctx) throws Exception {
		if (!node.isObject()) {
			return success(ctx);
		}

		Object documentLoader = ctx.get(Key.JSON_DOCUMENT_LOADER);
		Set<URI> contexts;
		if (documentLoader instanceof CachingDocumentLoader) {
			contexts = ((CachingDocumentLoader) documentLoader).getContexts();
		} else {
			contexts = Set.of();
		}

		// TODO Auto-generated method stub
		return null;
	}

	private void getValidations(JsonNode node, String entryPath, Set<URI> contexts) {

	}
}
