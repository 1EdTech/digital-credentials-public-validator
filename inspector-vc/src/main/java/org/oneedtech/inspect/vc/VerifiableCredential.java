package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.vc.VerifiableCredential.Type.AchievementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.ClrCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.EndorsementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.VerifiablePresentation;

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
 * A wrapper object for a verifiable credential. This contains e.g. the origin resource
 * and the extracted JSON data plus any other stuff Probes need.
 * @author mgylling
 */
public class VerifiableCredential extends AbstractBaseCredential  {
	final VerifiableCredential.Type credentialType;

    protected VerifiableCredential(Resource resource, JsonNode data, String jwt, Map<String, SchemaKey> schemas) {
        super(ID, resource, data, jwt, schemas);

		ArrayNode typeNode = (ArrayNode)jsonData.get("type");
		this.credentialType = VerifiableCredential.Type.valueOf(typeNode);
    }

	public String getCredentialType() {
		return credentialType.toString();
	}

	public ProofType getProofType() {
		return jwt == null ? ProofType.EMBEDDED : ProofType.EXTERNAL;
	}

	private static final Map<VerifiableCredential.Type, SchemaKey> schemas = new ImmutableMap.Builder<VerifiableCredential.Type, SchemaKey>()
			.put(AchievementCredential, Catalog.OB_30_ACHIEVEMENTCREDENTIAL_JSON)
			.put(ClrCredential, Catalog.CLR_20_CLRCREDENTIAL_JSON)
			.put(VerifiablePresentation, Catalog.CLR_20_CLRCREDENTIAL_JSON)
			.put(EndorsementCredential, Catalog.OB_30_ENDORSEMENTCREDENTIAL_JSON)
			.build();


	public enum Type {
		AchievementCredential,
		OpenBadgeCredential, 	//treated as an alias of AchievementCredential
		ClrCredential,
		EndorsementCredential,
		VerifiablePresentation,
		VerifiableCredential,  //this is an underspecifier in our context
		Unknown;

		public static VerifiableCredential.Type valueOf (ArrayNode typeArray) {
			if(typeArray != null) {
				Iterator<JsonNode> iter = typeArray.iterator();
				while(iter.hasNext()) {
					String value = iter.next().asText();
					if(value.equals("AchievementCredential") || value.equals("OpenBadgeCredential")) {
						return AchievementCredential;
					} else if(value.equals("ClrCredential")) {
						return ClrCredential;
					} else if(value.equals("VerifiablePresentation")) {
						return VerifiablePresentation;
					} else if(value.equals("EndorsementCredential")) {
						return EndorsementCredential;
					}
				}
			}
			return Unknown;
		}
	}

	public enum ProofType {
		EXTERNAL,
		EMBEDDED
	}

	@Override
	public String toString() {
		return MoreObjects.toStringHelper(this)
				.add("super", super.toString())
				.add("credentialType", credentialType)
				.toString();
	}

    public static class Builder extends AbstractBaseCredential.Builder<VerifiableCredential> {
        @Override
        public VerifiableCredential build() {
            // transform key of schemas map to string because the type of the key in the base map is generic
            // and our specific key is an Enum
            return new VerifiableCredential(getResource(), getJsonData(), getJwt(),
                schemas.entrySet().stream().collect(Collectors.toMap(
                                    entry -> entry.getKey().toString(),
                                    entry -> entry.getValue())));
        }
    }

	public static final String ID = VerifiableCredential.class.getCanonicalName();

}
