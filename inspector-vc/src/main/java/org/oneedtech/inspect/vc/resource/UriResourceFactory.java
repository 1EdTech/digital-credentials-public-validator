package org.oneedtech.inspect.vc.resource;

import java.net.URISyntaxException;

import org.oneedtech.inspect.util.resource.UriResource;

/**
 * Factory interface for URI resources
 * @author xaracil
 */
public interface UriResourceFactory {
	public UriResource of(String uri) throws URISyntaxException;
}
