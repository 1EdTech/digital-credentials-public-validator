package org.oneedtech.inspect.vc.resource;

import java.net.URI;
import java.net.URISyntaxException;

import org.oneedtech.inspect.util.resource.UriResource;

/**
 * Default factory for URIResources
 * @author xaracil
 */
public class DefaultUriResourceFactory implements UriResourceFactory {

	@Override
	public UriResource of(String uri) throws URISyntaxException {
		return new UriResource(new URI(uri));
	}

}
