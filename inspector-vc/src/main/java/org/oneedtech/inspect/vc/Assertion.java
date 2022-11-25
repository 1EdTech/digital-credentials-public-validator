package org.oneedtech.inspect.vc;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
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
    public List<String> getContext() {
        return List.of("https://w3id.org/openbadges/v2");
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

    public enum Type implements CredentialEnum {
		Assertion(List.of("Assertion")),
		BadgeClass(List.of("BadgeClass")),
        Unknown(Collections.emptyList());

        private final List<String> allowedTypeValues;

        Type(List<String> typeValues) {
            this.allowedTypeValues = typeValues;
        }

		public static Assertion.Type valueOf (JsonNode typeNode) {
			if(typeNode != null) {
                List<String> values = JsonNodeUtil.asStringList(typeNode);
                for (String value : values) {
                    if(value.equals("Assertion")) {
                        return Assertion;
                    }
                    if(value.equals("BadgeClass")) {
                        return BadgeClass;
                    }
                }
			}
			return Unknown;
        }

        @Override
        public List<String> getRequiredTypeValues() {
            return Collections.emptyList();
        }

        @Override
        public List<String> getAllowedTypeValues() {
            return allowedTypeValues;
        }
	}

    public static final String ID = Assertion.class.getCanonicalName();
}
