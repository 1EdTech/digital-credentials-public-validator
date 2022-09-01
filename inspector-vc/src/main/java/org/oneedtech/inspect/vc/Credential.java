package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.util.code.Defensives.*;
import static org.oneedtech.inspect.util.resource.ResourceType.*;
import static org.oneedtech.inspect.vc.Credential.Type.*;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * A wrapper object for a verifiable credential. This contains e.g. the origin resource 
 * and the extracted JSON data plus any other stuff Probes need.  
 * @author mgylling
 */
public class Credential extends GeneratedObject  {
	final Resource resource;
	final JsonNode jsonData;
	final Credential.Type credentialType;
	final String jwt;
	
	public Credential(Resource resource, JsonNode data, String jwt) {
		super(ID, GeneratedObject.Type.INTERNAL);
		this.resource = checkNotNull(resource);
		this.jsonData = checkNotNull(data);
		this.jwt = jwt; //may be null
				
		checkTrue(RECOGNIZED_PAYLOAD_TYPES.contains(resource.getType()));
				
		ArrayNode typeNode = (ArrayNode)jsonData.get("type");
		this.credentialType = Credential.Type.valueOf(typeNode);
	}
	
	public Credential(Resource resource, JsonNode data) {
		this(resource, data, null);
	}
	
	public Resource getResource() {
		return resource;
	}
	
	public JsonNode getJson() {
		return jsonData;
	}

	public Credential.Type getCredentialType() {
		return credentialType;
	}

	public Optional<String> getJwt() {
		return Optional.ofNullable(jwt);
	}
	
	public ProofType getProofType() {
		if(jwt == null) return ProofType.EMBEDDED;
		return ProofType.EXTERNAL;
	}
	
	
	private static final Map<Credential.Type, SchemaKey> schemas = new ImmutableMap.Builder<Credential.Type, SchemaKey>()
			.put(AchievementCredential, Catalog.OB_30_ACHIEVEMENTCREDENTIAL_JSON)
			.put(ClrCredential, Catalog.OB_30_ACHIEVEMENTCREDENTIAL_JSON)
			.put(EndorsementCredential, Catalog.OB_30_ENDORSEMENTCREDENTIAL_JSON)
			.put(VerifiablePresentation, Catalog.CLR_20_CLRCREDENTIAL_JSON)
			.build();
	
	/**
	 * Get the canonical schema for this credential if such exists.
	 */
	public Optional<SchemaKey> getSchemaKey() {
		return Optional.ofNullable(schemas.get(credentialType));		
	}
	
	public enum Type {
		AchievementCredential,
		OpenBadgeCredential, 	//treated as an alias of AchievementCredential
		ClrCredential, //NOT a duplicate of OB this does not use an alias and we ONLY use 'ClrCredential' as the base type
		EndorsementCredential,
		VerifiablePresentation,
		VerifiableCredential,  //this is an underspecifier in our context
		Unknown;	
		
		public static Credential.Type valueOf (ArrayNode typeArray) {
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
				.add("resource", resource.getID())
				.add("resourceType", resource.getType())
				.add("credentialType", credentialType)
				.add("json", jsonData)
				.toString();
	}
	
	public static final String ID = Credential.class.getCanonicalName();
	public static final List<ResourceType> RECOGNIZED_PAYLOAD_TYPES = List.of(SVG, PNG, JSON, JWT);
	public static final String CREDENTIAL_KEY = "CREDENTIAL_KEY";
		
}
