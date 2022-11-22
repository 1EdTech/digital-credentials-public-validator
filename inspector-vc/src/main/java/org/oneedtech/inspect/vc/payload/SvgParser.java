package org.oneedtech.inspect.vc.payload;

import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import java.io.InputStream;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.XMLEvent;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.xml.XMLInputFactoryCache;
import org.oneedtech.inspect.vc.AbstractBaseCredential;

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
	public AbstractBaseCredential parse(Resource resource, RunContext ctx)  throws Exception {
		final QNames qNames = (QNames) ctx.get(RunContext.Key.SVG_CREDENTIAL_QNAME);

		checkTrue(resource.getType() == ResourceType.SVG);

		try(InputStream is = resource.asByteSource().openStream()) {
			XMLEventReader reader = XMLInputFactoryCache.getInstance().createXMLEventReader(is);
			while(reader.hasNext()) {
				XMLEvent ev = reader.nextEvent();
				if(isEndElem(ev, qNames.getCredentialElem())) break;
				if(isStartElem(ev, qNames.getCredentialElem())) {
					Attribute verifyAttr = ev.asStartElement().getAttributeByName(qNames.getVerifyElem());
					if(verifyAttr != null) {
						String jwt = verifyAttr.getValue();
						JsonNode node = fromJwt(jwt, ctx);
						return getBuilder(ctx).resource(resource).jsonData(node).jwt(jwt).build();
					} else {
						while(reader.hasNext()) {
							ev = reader.nextEvent();
							if(isEndElem(ev, qNames.getCredentialElem())) break;
							if(ev.getEventType() == XMLEvent.CHARACTERS) {
								Characters chars = ev.asCharacters();
								if(!chars.isWhiteSpace()) {
									JsonNode node = fromString(chars.getData(), ctx);
									return getBuilder(ctx).resource(resource).jsonData(node).build();
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

	private static final QName OB_CRED_VERIFY_ATTR = new QName("verify");

	/*
	 * Know QNames whre the credential is baked into the SVG
	 */
	public enum QNames {
		OB20(new QName("http://openbadges.org", "assertion"), OB_CRED_VERIFY_ATTR),
		OB30(new QName("https://purl.imsglobal.org/ob/v3p0", "credential"), OB_CRED_VERIFY_ATTR),
		CLR20(new QName("https://purl.imsglobal.org/clr/v2p0", "credential"), OB_CRED_VERIFY_ATTR);

		private final QName credentialElem;
		private final QName verifyElem;

		private QNames(QName credentialElem, QName verifyElem) {
			this.credentialElem = credentialElem;
			this.verifyElem = verifyElem;
		}

		public QName getCredentialElem() {
			return credentialElem;
		}

		public QName getVerifyElem() {
			return verifyElem;
		}

	}
}
