package org.oneedtech.inspect.vc.probe;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Optional;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.XMLEvent;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.detect.TypeDetector;
import org.oneedtech.inspect.util.xml.XMLInputFactoryCache;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Splitter;

/**
 * A probe that verifies that the incoming credential resource is of a recognized type, 
 * and if so extracts and stores the VC json data (a 'Credential' instance) in the RunContext.   
 * @author mgylling
 */
public class CredentialTypeProbe extends Probe<Resource> {
			
	@Override
	public ReportItems run(Resource resource, RunContext context) throws Exception {
		
		Credential crd = null; 
		try {
			Optional<ResourceType> type = TypeDetector.detect(resource, true);
			
			if(type.isPresent()) {
				resource.setType(type.get());
				if(type.get() == ResourceType.PNG) {
					crd = new Credential(resource, fromPNG(resource, context));
				} else if(type.get() == ResourceType.SVG) {
					crd = new Credential(resource, fromSVG(resource, context));
				} else if(type.get() == ResourceType.JSON) {
					crd = new Credential(resource, fromJson(resource, context));
				} else if(type.get() == ResourceType.JWT) {
					crd = new Credential(resource, fromJWT(resource, context));
				}
			} 
					
			if(crd != null) {
				context.addGeneratedObject(crd);
				return success(this, context);		
			} else {
				return fatal("Could not detect credential type", context);	
			}
			
		} catch (Exception e) {
			return fatal("Error while detecting credential type: " + e.getMessage(), context);
		}		
	}

	/**
	 * Extract the JSON data from a baked PNG credential.
	 * @param context 
	 * @throws Exception 
	 */
	private JsonNode fromPNG(Resource resource, RunContext context) throws Exception {
		//TODO @Miles - note: iTxt chunk is either plain json or jwt	
		try(InputStream is = resource.asByteSource().openStream()) {
			
		}
		return null;
	}
	
	/**
	 * Extract the JSON data from a baked SVG credential.
	 * @param context 
	 * @throws Exception 
	 */
	private JsonNode fromSVG(Resource resource, RunContext context) throws Exception {
		String json = null;
		try(InputStream is = resource.asByteSource().openStream()) {
			XMLEventReader reader = XMLInputFactoryCache.getInstance().createXMLEventReader(is);
			while(reader.hasNext()) {
				XMLEvent ev = reader.nextEvent();
				if(ev.isStartElement() && ev.asStartElement().getName().equals(OB_CRED_ELEM)) {
					Attribute verifyAttr = ev.asStartElement().getAttributeByName(OB_CRED_VERIFY_ATTR);
					if(verifyAttr != null) {
						json = decodeJWT(verifyAttr.getValue());
						break;
					} else {
						while(reader.hasNext()) {
							ev = reader.nextEvent();
							if(ev.isEndElement() && ev.asEndElement().getName().equals(OB_CRED_ELEM)) {
								break;
							}
							if(ev.getEventType() == XMLEvent.CHARACTERS) {
								Characters chars = ev.asCharacters();
								if(!chars.isWhiteSpace()) {
									json = chars.getData();
									break;
								}
							}
						}						
					}					
				}	
				if(json!=null) break;
			}
		}	
		if(json == null) throw new IllegalArgumentException("No credential inside SVG");		
		return fromString(json, context);
	}
	
	/**
	 * Create a JsonNode object from a raw JSON resource.
	 * @param context 
	 */
	private JsonNode fromJson(Resource resource, RunContext context) throws Exception {
		return fromString(resource.asByteSource().asCharSource(UTF_8).read(), context);
	}
		
	/**
	 * Create a JsonNode object from a String.
	 */
	private JsonNode fromString(String json, RunContext context) throws Exception {
		return ((ObjectMapper)context.get(RunContext.Key.JACKSON_OBJECTMAPPER)).readTree(json);
	}
	
	/**
	 * Create a JsonNode object from a JWT resource.
	 * @param context 
	 */
	private JsonNode fromJWT(Resource resource, RunContext context) throws Exception {
		return fromString(decodeJWT(resource.asByteSource().asCharSource(UTF_8).read()), context);
	}
	
	/**
	 * Decode as per https://www.imsglobal.org/spec/ob/v3p0/#jwt-proof
	 * @return The decoded JSON String
	 */
	private String decodeJWT(String jwt) {
		List<String> parts = Splitter.on('.').splitToList(jwt);
		if(parts.size() != 3) throw new IllegalArgumentException("invalid jwt");
		
		final Decoder decoder = Base64.getUrlDecoder();
		String joseHeader = new String(decoder.decode(parts.get(0)));
		String jwtPayload = new String(decoder.decode(parts.get(1)));
		String jwsSignature = new String(decoder.decode(parts.get(2)));
				
		//TODO @Miles
		
		return null;	
	}
	
	private static final QName OB_CRED_ELEM = new QName("https://purl.imsglobal.org/ob/v3p0", "credential");
	private static final QName OB_CRED_VERIFY_ATTR = new QName("verify");
}
