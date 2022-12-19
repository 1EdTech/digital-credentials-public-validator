package org.oneedtech.inspect.vc.resource;

import java.net.URI;
import java.net.URISyntaxException;

import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import com.apicatalog.jsonld.loader.DocumentLoader;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * UriResource factory for test, resolving local references
 * @author xaracil
 */
public class TestUriResourceFactory implements UriResourceFactory {

	final DocumentLoader documentLoader;

	public TestUriResourceFactory(DocumentLoader documentLoader) {
		this.documentLoader = documentLoader;
	}

	@Override
	public UriResource of(String uriString) throws URISyntaxException {
		URI uri = new URI(uriString);
		if (documentLoader instanceof CachingDocumentLoader) {
			URI resolvedUri = ((CachingDocumentLoader.HttpLoader) ConfigurableDocumentLoader.getDefaultHttpLoader()).resolve(uri);
			uri = resolvedUri;
		}
		return new UriResource(uri);
	}

}
