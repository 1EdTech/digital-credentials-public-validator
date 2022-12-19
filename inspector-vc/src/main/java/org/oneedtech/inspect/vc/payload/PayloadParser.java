package org.oneedtech.inspect.vc.payload;

import static com.apicatalog.jsonld.StringUtils.isBlank;

import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;

/**
 * Abstract base for extracting Credential instances from payloads.
 * @author mgylling
 */
public abstract class PayloadParser {

	public abstract boolean supports(ResourceType type);

	public abstract Credential parse(Resource source, RunContext ctx) throws Exception;

	@SuppressWarnings("rawtypes")
	public static Credential.Builder getBuilder(RunContext context) {
		return ((Credential.Builder) context.get(RunContext.Key.GENERATED_OBJECT_BUILDER));
	}

	protected static JsonNode fromString(String json, RunContext context) throws Exception {
		return ((ObjectMapper)context.get(RunContext.Key.JACKSON_OBJECTMAPPER)).readTree(json);
	}

	/**
	 * Decode as per https://www.imsglobal.org/spec/ob/v3p0/#jwt-proof
	 * @return The decoded JSON String
	 */
	public static JsonNode fromJwt(String jwt, RunContext context) throws Exception {
		List<String> parts = Splitter.on('.').splitToList(jwt);
		if(parts.size() != 3) throw new IllegalArgumentException("invalid jwt");

		final Decoder decoder = Base64.getUrlDecoder();
		/*
		 * For this step we are only deserializing the stored badge out of the payload.
		 * The entire jwt is stored separately for signature verification later.
		 */
		String jwtPayload = new String(decoder.decode(parts.get(1)));

		//Deserialize and fetch the credential node from the object
		JsonNode outerPayload = fromString(jwtPayload, context);
		String nodeName = (String) context.get(Key.JWT_CREDENTIAL_NODE_NAME);
		if (isBlank(nodeName)) {
			return outerPayload;
		}
		JsonNode vcNode = outerPayload.get(nodeName);

		return vcNode;
	}

}
