package org.oneedtech.inspect.vc.payload;

import static org.oneedtech.inspect.util.code.Defensives.checkTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.Credential;

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

			TextChunkResult textChunkResult = readTextChunk(is, credentialKey.getNodeName(), credentialKey.allowsInconsistentItXt(), credentialKey.allowsTeXT());
			String vcString = textChunkResult != null ? textChunkResult.text : null;
			String jwtString = null;
			JsonNode vcNode = null;

			if(textChunkResult == null || vcString == null) {
				throw new IllegalArgumentException("No credential inside PNG");
			}

			vcString = vcString.trim();
			if(vcString.charAt(0) != '{'){
				// check if the content is an URI and we allow URI location in value
				boolean isJwt = true;
				if (credentialKey.allowsUriLocationInValue() || textChunkResult.needHttpFetch) {
					try {
						/** Legacy PNGs in OB 2.0
						 * The pre-specified behavior of badge baking worked differently.
						 * Instead of baking the whole assertion or signature into an iTXt:openbadges chunk,
						 * the URL pointing to the hosted assertion was baked into a tEXt:openbadges chunk.
						 * In order to get the full assertion, an additional HTTP request must be made after
						 * extracting the URL from the tEXt chunk.
						 */
						URI uri = new URI(vcString);
						vcNode = fromUri(uri, ctx);
						isJwt = false;
					} catch (URISyntaxException ignored) {
					}
				}
				if (isJwt) {
					//This is a jwt.  Fetch either the 'vc' out of the payload and save the string for signature verification.
					jwtString = vcString;
					vcNode = fromJwt(vcString, ctx);
				}
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

	/**
	 * Scans PNG text chunks (tEXt, iTXt) directly at the byte level and returns the text of
	 * the first chunk whose keyword matches, skipping every other chunk by its declared length.
	 * javax.imageio's PNGImageReader parses every chunk in the file up front and aborts entirely if
	 * any one of them is malformed, even when it has nothing to do with the credential we're after.
	 * Reading chunks manually means a broken, unrelated chunk elsewhere in the file can't prevent us
	 * from finding the one we actually need.
	 */
	private TextChunkResult readTextChunk(InputStream is, String keyword, boolean allowInconsistentItXt, boolean allowTeXT) throws IOException {
		DataInputStream dis = new DataInputStream(is);
		dis.readFully(new byte[8]); //PNG signature, already validated by ResourceType detection

		while (true) {
			int length;
			try {
				length = dis.readInt();
			} catch (EOFException e) {
				return null;
			}
			byte[] type = new byte[4];
			dis.readFully(type);
			String typeName = new String(type, StandardCharsets.US_ASCII);
			byte[] data = new byte[length];
			dis.readFully(data);
			dis.skipBytes(4); //CRC

			if ("IEND".equals(typeName)) {
				return null;
			}

			if (typeName.equals("iTXt")) {
				String text = parseITXt(data, keyword, allowInconsistentItXt);
				if (text != null) {
					return new TextChunkResult(false, text);
				}
			}
			if (allowTeXT && typeName.equals("tEXt")) {
				String text = parseTEXt(data, keyword);
				if (text != null) {
					return new TextChunkResult(true, text);
				}
			}
		}
	}

	private String parseITXt(byte[] data, String keyword, boolean allowInconsistentItXt) {
		int nul = indexOf(data, 0, data.length);
		if (nul < 0 || !matchesKeyword(data, nul, keyword)) {
			return null;
		}
		//A well-formed iTXt chunk has a compression flag (0 or 1) and method (0) right after the
		//keyword, followed by null-terminated language-tag and translated-keyword fields. Some
		//badge-baking tools write plain text directly after the keyword instead, so the byte we'd
		//read as the compression flag is really the start of the text. Only trust the strict
		//structure when it actually looks like one.
		if (nul + 2 < data.length) {
			byte flag = data[nul + 1];
			byte method = data[nul + 2];
			if ((flag == 0 || flag == 1) && method == 0) {
				int langEnd = indexOf(data, nul + 3, data.length);
				if (langEnd >= 0) {
					int translatedEnd = indexOf(data, langEnd + 1, data.length);
					if (translatedEnd >= 0) {
						int textStart = translatedEnd + 1;
						int textLength = data.length - textStart;
						if (flag == 0) {
							return new String(data, textStart, textLength, StandardCharsets.UTF_8);
						}
						byte[] inflated = inflate(data, textStart, textLength);
						return inflated == null ? null : new String(inflated, StandardCharsets.UTF_8);
					}
				}
			}
		}
		//Malformed/legacy chunk: treat everything after the keyword as raw text, like a tEXt chunk.
		if (!allowInconsistentItXt) {
			return null;
		}
		return new String(data, nul + 1, data.length - nul - 1, StandardCharsets.UTF_8);
	}

	private String parseTEXt(byte[] data, String keyword) {
		int nul = indexOf(data, 0, data.length);
		if (nul < 0 || !matchesKeyword(data, nul, keyword)) {
			return null;
		}
		return new String(data, nul + 1, data.length - nul - 1, StandardCharsets.ISO_8859_1);
	}

	private boolean matchesKeyword(byte[] data, int nul, String keyword) {
		return new String(data, 0, nul, StandardCharsets.ISO_8859_1).equals(keyword);
	}

	private int indexOf(byte[] data, int from, int to) {
		for (int i = from; i < to; i++) {
			if (data[i] == 0) {
				return i;
			}
		}
		return -1;
	}

	private byte[] inflate(byte[] data, int offset, int length) {
		Inflater inflater = new Inflater();
		inflater.setInput(data, offset, length);
		ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(length * 2, 64));
		byte[] buffer = new byte[4096];
		try {
			while (!inflater.finished()) {
				int count = inflater.inflate(buffer);
				if (count == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
					break;
				}
				out.write(buffer, 0, count);
			}
			return out.toByteArray();
		} catch (DataFormatException e) {
			return null;
		} finally {
			inflater.end();
		}
	}

	public enum Keys {
		OB20("openbadges", true, true, true),
		OB30("openbadgecredential", false, false, false),
		CLR20("clrcredential", false, false, false);

		private String nodeName;
		private boolean allowUriLocationInValue;
		private boolean allowInconsistentItXt;
		private boolean allowTeXT;

		private Keys(String nodeName, boolean allowUriLocationInValue, boolean allowInconsistentItXt, boolean allowTeXT) {
			this.nodeName = nodeName;
			this.allowUriLocationInValue = allowUriLocationInValue;
			this.allowInconsistentItXt = allowInconsistentItXt;
			this.allowTeXT = allowTeXT;
		}

		public String getNodeName() {
			return nodeName;
		}

		public boolean allowsUriLocationInValue() {
			return allowUriLocationInValue;
		}

		public boolean allowsInconsistentItXt() {
			return allowInconsistentItXt;
		}

		public boolean allowsTeXT() {
			return allowTeXT;
		}
	}

	private static class TextChunkResult {
		boolean needHttpFetch;
		String text;

		public TextChunkResult(boolean needHttpFetch, String text) {
			this.needHttpFetch = needHttpFetch;
			this.text = text;
		}
	}
}
