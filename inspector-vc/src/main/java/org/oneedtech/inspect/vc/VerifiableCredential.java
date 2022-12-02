package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.vc.VerifiableCredential.Type.AchievementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.ClrCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.EndorsementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.VerifiablePresentation;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * A wrapper object for a verifiable credential. This contains e.g. the origin resource
 * and the extracted JSON data plus any other stuff Probes need.
 * @author mgylling
 */
public class VerifiableCredential extends Credential  {
	final VerifiableCredential.Type credentialType;

    protected VerifiableCredential(Resource resource, JsonNode data, String jwt, Map<CredentialEnum, SchemaKey> schemas, String issuedOnPropertyName, String expiresAtPropertyName) {
        super(ID, resource, data, jwt, schemas, issuedOnPropertyName, expiresAtPropertyName);

        JsonNode typeNode = jsonData.get("type");
		this.credentialType = VerifiableCredential.Type.valueOf(typeNode);
    }

	public CredentialEnum getCredentialType() {
		return credentialType;
	}

	public ProofType getProofType() {
		return jwt == null ? ProofType.EMBEDDED : ProofType.EXTERNAL;
	}

	private static final Map<CredentialEnum, SchemaKey> schemas = new ImmutableMap.Builder<CredentialEnum, SchemaKey>()
			.put(AchievementCredential, Catalog.OB_30_ACHIEVEMENTCREDENTIAL_JSON)
			.put(ClrCredential, Catalog.CLR_20_CLRCREDENTIAL_JSON)
			.put(VerifiablePresentation, Catalog.CLR_20_CLRCREDENTIAL_JSON)
			.put(EndorsementCredential, Catalog.OB_30_ENDORSEMENTCREDENTIAL_JSON)
			.build();

	private static final Map<Set<VerifiableCredential.Type>, List<String>> contextMap = new ImmutableMap.Builder<Set<VerifiableCredential.Type>, List<String>>()
			.put(Set.of(Type.OpenBadgeCredential, AchievementCredential, EndorsementCredential),
					List.of("https://www.w3.org/2018/credentials/v1",
							//"https://purl.imsglobal.org/spec/ob/v3p0/context.json")) //dev legacy
							"https://purl.imsglobal.org/spec/ob/v3p0/context.json"))
			.put(Set.of(ClrCredential),
					List.of("https://www.w3.org/2018/credentials/v1",
		//							"https://dc.imsglobal.org/draft/clr/v2p0/context", //dev legacy
		//							"https://purl.imsglobal.org/spec/ob/v3p0/context.json")) //dev legacy
							"https://purl.imsglobal.org/spec/clr/v2p0/context.json",
							"https://purl.imsglobal.org/spec/ob/v3p0/context.json"))

			.build();

	public enum Type implements CredentialEnum {
		AchievementCredential(Collections.emptyList()),
		OpenBadgeCredential(List.of("OpenBadgeCredential", "AchievementCredential")), 	//treated as an alias of AchievementCredential
		ClrCredential(List.of("ClrCredential")),
		EndorsementCredential(List.of("EndorsementCredential")),
		VerifiablePresentation(Collections.emptyList()),
		VerifiableCredential(List.of("VerifiableCredential")),  //this is an underspecifier in our context
		Unknown(Collections.emptyList());

		private final List<String> allowedTypeValues;

		Type(List<String> allowedTypeValues) {
            this.allowedTypeValues = allowedTypeValues;
        }

		public static VerifiableCredential.Type valueOf (JsonNode typeNode) {
			if(typeNode != null) {
				List<String> values = JsonNodeUtil.asStringList(typeNode);
				for (String value : values) {
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

		@Override
		public List<String> getRequiredTypeValues() {
			return List.of("VerifiableCredential");
		}

		@Override
        public List<String> getAllowedTypeValues() {
            return allowedTypeValues;
        }

		@Override
		public List<String> getContextUris() {
			return contextMap.get(contextMap.keySet()
				.stream()
				.filter(s->s.contains(this))
				.findFirst()
				.orElseThrow(()-> new IllegalArgumentException(this.name() + " not recognized")));
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

    public static class Builder extends Credential.Builder<VerifiableCredential> {
        @Override
        public VerifiableCredential build() {
            return new VerifiableCredential(getResource(), getJsonData(), getJwt(), schemas, ISSUED_ON_PROPERTY_NAME, EXPIRES_AT_PROPERTY_NAME);
        }
    }

	public static final String ID = VerifiableCredential.class.getCanonicalName();
	private static final String ISSUED_ON_PROPERTY_NAME = "issuanceDate";
	private static final String EXPIRES_AT_PROPERTY_NAME = "expirationDate";
	public static final String JWT_NODE_NAME = "vc";
}
