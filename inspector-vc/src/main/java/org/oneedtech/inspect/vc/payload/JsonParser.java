package org.oneedtech.inspect.vc.payload;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.AbstractBaseCredential;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * A credential extractor for JSON files.
 * @author mgylling
 */
public final class JsonParser extends PayloadParser {

	@Override
	public boolean supports(ResourceType type) {
		return type == ResourceType.JSON;
	}

	@Override
	public AbstractBaseCredential parse(Resource resource, RunContext ctx)  throws Exception {
		checkTrue(resource.getType() == ResourceType.JSON);
		String json = resource.asByteSource().asCharSource(UTF_8).read();
		JsonNode node = fromString(json, ctx);

		return getBuilder(ctx)
				.resource(resource)
				.jsonData(node)
				.build();
	}

}
