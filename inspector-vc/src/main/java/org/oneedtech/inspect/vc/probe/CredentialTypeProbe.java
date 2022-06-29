package org.oneedtech.inspect.vc.probe;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.List;
import java.util.Optional;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.metadata.IIOMetadata;
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
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

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
					crd = fromPNG(resource, context);
				} else if(type.get() == ResourceType.SVG) {
					crd = fromSVG(resource, context);
				} else if(type.get() == ResourceType.JSON) {
					crd = fromJson(resource, context);
				} else if(type.get() == ResourceType.JWT) {
					crd = fromJWT(resource, context);
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
	private Credential fromPNG(Resource resource, RunContext context) throws Exception {	
		try(InputStream is = resource.asByteSource().openStream()) {
			ImageReader imageReader = ImageIO.getImageReadersByFormatName("png").next();
			imageReader.setInput(ImageIO.createImageInputStream(is), true);
			IIOMetadata metadata = imageReader.getImageMetadata(0);

			String credentialString = null;
			String jwtString = null;
			String formatSearch = null;
			JsonNode credential = null;
			String[] names = metadata.getMetadataFormatNames();
			int length = names.length;
			for (int i = 0; i < length; i++)
			{
				//Check all names rather than limiting to PNG format to remain malleable through any library changes.  (Could limit to "javax_imageio_png_1.0")
				formatSearch = getOpenBadgeCredentialNodeText(metadata.getAsTree(names[i]));
				if(formatSearch != null) { credentialString = formatSearch; }
			}

			if(credentialString == null) { throw new IllegalArgumentException("No credential inside PNG"); }

			credentialString = credentialString.trim();
			if(credentialString.charAt(0) != '{'){
				//This is a jwt.  Fetch either the 'vc' out of the payload and save the string for signature verification.
				jwtString = credentialString;
				credential = decodeJWT(credentialString,context);
			}
			else {
				credential = buildNodeFromString(credentialString, context);
			}
			
			return new Credential(resource, credential, jwtString);
		}
	}
	
	/**
	 * Extract the JSON data from a baked SVG credential.
	 * @param context 
	 * @throws Exception 
	 */
	private Credential fromSVG(Resource resource, RunContext context) throws Exception {
		String json = null;
		String jwtString = null;
		JsonNode credential = null;;
		try(InputStream is = resource.asByteSource().openStream()) {
			XMLEventReader reader = XMLInputFactoryCache.getInstance().createXMLEventReader(is);
			while(reader.hasNext()) {
				XMLEvent ev = reader.nextEvent();
				if(ev.isStartElement() && ev.asStartElement().getName().equals(OB_CRED_ELEM)) {
					Attribute verifyAttr = ev.asStartElement().getAttributeByName(OB_CRED_VERIFY_ATTR);
					if(verifyAttr != null) {
						jwtString = verifyAttr.getValue();
						credential = decodeJWT(verifyAttr.getValue(), context);
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
									credential = buildNodeFromString(json, context);
									break;
								}
							}
						}					
					}			
				}
				if(credential!=null) break;
			}
		}	
		if(credential == null) throw new IllegalArgumentException("No credential inside SVG");	
		return new Credential(resource, credential, jwtString);
	}
	
	/**
	 * Create a Credential object from a raw JSON resource.
	 * @param context 
	 */
	private Credential fromJson(Resource resource, RunContext context) throws Exception {
		return new Credential(resource, buildNodeFromString(resource.asByteSource().asCharSource(UTF_8).read(), context), null);
	}
	
	/**
	 * Create a Credential object from a JWT resource.
	 * @param context 
	 */
	private Credential fromJWT(Resource resource, RunContext context) throws Exception {
		return new Credential(
			resource, 
			decodeJWT(
				resource.asByteSource().asCharSource(UTF_8).read(),
				context
			)
			, resource.asByteSource().asCharSource(UTF_8).read()
		);
	}

	/**
	 * Create a JsonNode object from a String.
	 */
	private JsonNode buildNodeFromString(String json, RunContext context) throws Exception {
		return ((ObjectMapper)context.get(RunContext.Key.JACKSON_OBJECTMAPPER)).readTree(json);
	}
	
	/**
	 * Decode as per https://www.imsglobal.org/spec/ob/v3p0/#jwt-proof
	 * @return The decoded JSON String
	 */
	private JsonNode decodeJWT(String jwt, RunContext context) throws Exception {
		List<String> parts = Splitter.on('.').splitToList(jwt);
		if(parts.size() != 3) throw new IllegalArgumentException("invalid jwt");
		
		final Decoder decoder = Base64.getUrlDecoder();
		//For this step we are only deserializing the stored badge out of the payload.  The entire jwt is stored separately for
		//signature verification later.
		String jwtPayload = new String(decoder.decode(parts.get(1)));

		//Deserialize and fetch the 'vc' node from the object
		JsonNode outerPayload = buildNodeFromString(jwtPayload, context);
		JsonNode vcNode = outerPayload.get("vc");

		return vcNode;
	}

	private String getOpenBadgeCredentialNodeText(Node node){
        NamedNodeMap attributes = node.getAttributes();

		//If this node is labeled with the attribute keyword: 'openbadgecredential' it is the right one.
		if(attributes.getNamedItem("keyword") != null && attributes.getNamedItem("keyword").getNodeValue().equals("openbadgecredential")){
			Node textAttribute = attributes.getNamedItem("text");
			if(textAttribute != null) { return textAttribute.getNodeValue(); }
		}

		//iterate over all children depth first and search for the credential node.
		Node child = node.getFirstChild();
		while (child != null)
        {
            String nodeValue = getOpenBadgeCredentialNodeText(child);
			if(nodeValue != null) { return nodeValue; }
            child = child.getNextSibling();
        }

		//Return null if we haven't found anything at this recursive depth.
		return null;
	}
	
	private static final QName OB_CRED_ELEM = new QName("https://purl.imsglobal.org/ob/v3p0", "credential");
	private static final QName OB_CRED_VERIFY_ATTR = new QName("verify");
}
