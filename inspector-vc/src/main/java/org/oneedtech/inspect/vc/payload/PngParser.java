package org.oneedtech.inspect.vc.payload;

import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.metadata.IIOMetadata;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.Credential;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A credential extractor for PNG images.
 * @author mgylling
 */
public final class PngParser extends PayloadParser {

	@Override
	public boolean supports(ResourceType type) {
		return type == ResourceType.PNG;
	}

	@Override
	public Credential parse(Resource resource, RunContext ctx) throws Exception {

		checkTrue(resource.getType() == ResourceType.PNG);

		try(InputStream is = resource.asByteSource().openStream()) {
			final Keys credentialKey = (Keys) ctx.get(RunContext.Key.PNG_CREDENTIAL_KEY);

			ImageReader imageReader = ImageIO.getImageReadersByFormatName("png").next();
			imageReader.setInput(ImageIO.createImageInputStream(is), true);
			IIOMetadata metadata = imageReader.getImageMetadata(0);

			String vcString = null;
			String jwtString = null;
			String formatSearch = null;
			JsonNode vcNode = null;

			String[] names = metadata.getMetadataFormatNames();
			int length = names.length;
			for (int i = 0; i < length; i++) {
				//Check all names rather than limiting to PNG format to remain malleable through any library changes.  (Could limit to "javax_imageio_png_1.0")
				formatSearch = getOpenBadgeCredentialNodeText(metadata.getAsTree(names[i]), credentialKey);
				if(formatSearch != null) {
					vcString = formatSearch;
					break;
				}
			}

			if(vcString == null) {
				throw new IllegalArgumentException("No credential inside PNG");
			}

			vcString = vcString.trim();
			if(vcString.charAt(0) != '{'){
				//This is a jwt.  Fetch either the 'vc' out of the payload and save the string for signature verification.
				jwtString = vcString;
				vcNode = fromJwt(vcString, ctx);
			}
			else {
				vcNode = fromString(vcString, ctx);
			}

			return getBuilder(ctx)
					.resource(resource)
					.jsonData(vcNode)
					.jwt(jwtString)
					.build();
		}
	}

	private String getOpenBadgeCredentialNodeText(Node node, Keys credentialKey){
        NamedNodeMap attributes = node.getAttributes();

		//If this node is labeled with the attribute keyword: 'openbadgecredential' it is the right one.
        Node keyword = attributes.getNamedItem("keyword");
		if(keyword != null && keyword.getNodeValue().equals(credentialKey.getNodeName())){
			Node textAttribute = attributes.getNamedItem("text");
			if(textAttribute != null) {
				return textAttribute.getNodeValue();
			}
		}

		//iterate over all children depth first and search for the credential node.
		Node child = node.getFirstChild();
		while (child != null) {
            String nodeValue = getOpenBadgeCredentialNodeText(child, credentialKey);
			if(nodeValue != null) {
				return nodeValue;
			}
            child = child.getNextSibling();
        }

		//Return null if we haven't found anything at this recursive depth.
		return null;
	}

	public enum Keys {
		OB20("openbadges"),
		OB30("openbadgecredential"),
		CLR20("clrcredential");

		private String nodeName;

		private Keys(String nodeName) {
			this.nodeName = nodeName;
		}

		public String getNodeName() {
			return nodeName;
		}
	}
}
