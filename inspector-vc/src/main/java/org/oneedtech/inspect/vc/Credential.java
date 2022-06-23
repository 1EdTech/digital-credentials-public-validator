package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.util.code.Defensives.*;
import static org.oneedtech.inspect.util.resource.ResourceType.*;

import java.util.Iterator;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.GeneratedObject;
import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.google.common.base.MoreObjects;

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
		checkNotNull(resource, resource.getType(), data);
		ResourceType type = resource.getType();
		checkTrue(type == SVG || type == PNG || type == JSON || type == JWT, 
				"Unrecognized payload type: " + type.getName());
		this.resource = resource;
		this.jsonData = data;
		this.jwt = jwt;
		
		ArrayNode typeNode = (ArrayNode)jsonData.get("type");		
		this.credentialType = Credential.Type.valueOf(typeNode);
	}
		
	public Resource getResource() {
		return resource;
	}
	
	public JsonNode asJson() {
		return jsonData;
	}

	public Credential.Type getCredentialType() {
		return credentialType;
	}
	
	/**
	 * Get the canonical schema for this credential if such exists.
	 */
	public Optional<SchemaKey> getSchemaKey() {
		if(credentialType == Credential.Type.AchievementCredential) {
			return Optional.of(Catalog.OB_30_ACHIEVEMENTCREDENTIAL_JSON);
		} else if(credentialType == Credential.Type.VerifiablePresentation) {
			return Optional.of(Catalog.OB_30_VERIFIABLEPRESENTATION_JSON);
		} else if(credentialType == Credential.Type.EndorsementCredential) {
			return Optional.of(Catalog.OB_30_ENDORSEMENTCREDENTIAL_JSON);
		} 		
		return Optional.empty();
	}
	
	public enum Type {
		AchievementCredential,
		OpenBadgeCredential, 	//treated as an alias of AchievementCredential
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
		
}
