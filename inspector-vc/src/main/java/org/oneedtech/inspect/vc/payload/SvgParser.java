package org.oneedtech.inspect.vc.payload;

import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import java.io.InputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.XMLEvent;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.code.Defensives;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.xml.XMLInputFactoryCache;
import org.oneedtech.inspect.vc.Credential;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A credential extractor for SVG documents.
 * @author mgylling
 */
public final class SvgParser extends PayloadParser {

	@Override
	public boolean supports(ResourceType type) {
		return type == ResourceType.SVG;
	}

	@Override
	public Credential parse(Resource resource, RunContext ctx)  throws Exception {
		
		checkTrue(resource.getType() == ResourceType.SVG);
		
		try(InputStream is = resource.asByteSource().openStream()) {
			XMLEventReader reader = XMLInputFactoryCache.getInstance().createXMLEventReader(is);
			while(reader.hasNext()) {
				XMLEvent ev = reader.nextEvent();
				if(isEndElem(ev, OB_CRED_ELEM)) break;					
				if(isStartElem(ev, OB_CRED_ELEM)) {
					Attribute verifyAttr = ev.asStartElement().getAttributeByName(OB_CRED_VERIFY_ATTR);
					if(verifyAttr != null) {
						String jwt = verifyAttr.getValue();
						JsonNode node = fromJwt(jwt, ctx);
						return new Credential(resource, node, jwt);
					} else {
						while(reader.hasNext()) {
							ev = reader.nextEvent();
							if(isEndElem(ev, OB_CRED_ELEM)) break;							
							if(ev.getEventType() == XMLEvent.CHARACTERS) {
								Characters chars = ev.asCharacters();
								if(!chars.isWhiteSpace()) {									
									JsonNode node = fromString(chars.getData(), ctx);
									return new Credential(resource, node);
								}
							}
						}				
					}
				}
			} //while(reader.hasNext()) {
		}
		throw new IllegalArgumentException("No credential inside SVG");	
		
	}

	private boolean isEndElem(XMLEvent ev, QName name) {
		return ev.isEndElement() && ev.asEndElement().getName().equals(name);
	}
	
	private boolean isStartElem(XMLEvent ev, QName name) {
		return ev.isStartElement() && ev.asStartElement().getName().equals(name);
	}
	
	private static final QName OB_CRED_ELEM = new QName("https://purl.imsglobal.org/ob/v3p0", "credential");
	private static final QName OB_CRED_VERIFY_ATTR = new QName("verify");
}
