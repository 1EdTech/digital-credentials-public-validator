package org.oneedtech.inspect.vc;

import java.util.Iterator;
import java.util.Map;
import java.util.stream.Collectors;

import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * A wrapper object for a OB 2.0 assertion. This contains e.g. the origin resource
 * and the extracted JSON data plus any other stuff Probes need.
 * @author xaracil
 */
public class Assertion extends Credential {

	final Assertion.Type assertionType;

    protected Assertion(Resource resource, JsonNode data, String jwt, Map<String, SchemaKey> schemas) {
        super(ID, resource, data, jwt, schemas);

        JsonNode typeNode = jsonData.get("type");
		this.assertionType = Assertion.Type.valueOf(typeNode);
    }

    @Override
    public String getCredentialType() {
        return assertionType.toString();
    }

    @Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("super", super.toString())
				.add("assertionType", assertionType)
				.toString();
	}

	private static final Map<Assertion.Type, SchemaKey> schemas = new ImmutableMap.Builder<Assertion.Type, SchemaKey>()
			.put(Type.Assertion, Catalog.OB_21_ASSERTION_JSON)
			.build();

    public static class Builder extends Credential.Builder<Assertion> {

        @Override
        public Assertion build() {
            // transform key of schemas map to string because the type of the key in the base map is generic
            // and our specific key is an Enum
            return new Assertion(getResource(), getJsonData(), getJwt(),
                schemas.entrySet().stream().collect(Collectors.toMap(
                                    entry -> entry.getKey().toString(),
                                    entry -> entry.getValue())));
        }
    }

    public enum Type {
		Assertion,
        Unknown;

		public static Assertion.Type valueOf (JsonNode typeNode) {
			if(typeNode != null) {
                String value = typeNode.asText();
                if(value.equals("Assertion")) {
                    return Assertion;
                }
			}
			return Unknown;
		}
	}

    public static final String ID = Assertion.class.getCanonicalName();
}
