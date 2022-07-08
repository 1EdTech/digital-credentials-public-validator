package org.oneedtech.inspect.vc.payload;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A credential extractor for JWT files.
 * @author mgylling
 */
public final class JwtParser extends PayloadParser {

	@Override
	public boolean supports(ResourceType type) {
		return type == ResourceType.JWT;
	}

	@Override
	public Credential parse(Resource resource, RunContext ctx)  throws Exception {		
		checkTrue(resource.getType() == ResourceType.JWT);
		String jwt = resource.asByteSource().asCharSource(UTF_8).read();
		JsonNode node = fromJwt(jwt, ctx);		
		return new Credential(resource, node, jwt);				
	}

}
