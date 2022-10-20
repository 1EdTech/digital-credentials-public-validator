package org.oneedtech.inspect.vc.payload;

import static org.oneedtech.inspect.util.code.Defensives.checkNotNull;

import java.util.List;

import org.oneedtech.inspect.util.resource.Resource;

/**
 * A factory to create PayloadParser instances for various resource types.
 * @author mgylling
 */
public class PayloadParserFactory {
	private static final Iterable<PayloadParser> parsers = List.of(
			new PngParser(), new SvgParser(),
			new JsonParser(), new JwtParser());
	
	public static PayloadParser of(Resource resource) {
		checkNotNull(resource.getType());
		for(PayloadParser cex : parsers) {
			if(cex.supports(resource.getType())) return cex;
		}				
		throw new IllegalArgumentException();
	}
}
