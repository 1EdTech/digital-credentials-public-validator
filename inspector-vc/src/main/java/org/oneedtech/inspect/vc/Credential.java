package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.util.code.Defensives.*;
import static org.oneedtech.inspect.util.resource.ResourceType.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.base.MoreObjects;


/**
 * Base credential class for OB 2.0 Assertions and OB 3.0 and CLR 2.0 Credentials.
 * This contains e.g. the origin resource and the extracted JSON data.
 * @author xaracil
 */
public abstract class Credential extends GeneratedObject {
	final Resource resource;
	final JsonNode jsonData;
	final String jwt;
    final Map<String, SchemaKey> schemas;

    protected Credential(String id, Resource resource, JsonNode data, String jwt, Map<String, SchemaKey> schemas) {
		super(id, GeneratedObject.Type.INTERNAL);
		this.resource = checkNotNull(resource);
		this.jsonData = checkNotNull(data);
		this.jwt = jwt; //may be null
        this.schemas = schemas;

		checkTrue(RECOGNIZED_PAYLOAD_TYPES.contains(resource.getType()));
	}

    public Resource getResource() {
        return resource;
    }

    public JsonNode getJson() {
        return jsonData;
    }

    public Optional<String> getJwt() {
		return Optional.ofNullable(jwt);
	}

    /**
	 * Get the canonical schema for this credential if such exists.
	 */
	public Optional<SchemaKey> getSchemaKey() {
		return Optional.ofNullable(schemas.get(getCredentialType()));
	}

    public abstract String getCredentialType();

    public abstract List<String> getContext();

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("resource", resource.getID())
				.add("resourceType", resource.getType())
				.add("json", jsonData)
				.add("jwt", jwt)
				.toString();
	}

	public static final List<ResourceType> RECOGNIZED_PAYLOAD_TYPES = List.of(SVG, PNG, JSON, JWT);
	public static final String CREDENTIAL_KEY = "CREDENTIAL_KEY";

    public interface CredentialEnum {
        List<String> getRequiredTypeValues();
        List<String> getAllowedTypeValues();
    }

	public abstract static class Builder<B extends Credential> {
        private Resource resource;
        private JsonNode jsonData;
        private String jwt;

        public abstract B build();

        public Builder<B> resource(Resource resource) {
            this.resource = resource;
            return this;
        }

        public Builder<B> jsonData(JsonNode node) {
            this.jsonData = node;
            return this;
        }

        public Builder<B> jwt(String jwt) {
            this.jwt = jwt;
            return this;
        }

        protected Resource getResource() {
            return resource;
        }

        protected JsonNode getJsonData() {
            return jsonData;
        }

        protected String getJwt() {
            return jwt;
        }
	}

}
