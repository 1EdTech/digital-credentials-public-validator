package org.oneedtech.inspect.vc.util;

import java.net.URI;
import java.net.URL;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.google.common.io.Resources;

public class CachingDocumentLoaderTests {

	@Test
	void testStaticCachedDocumentBundled() {
		Assertions.assertDoesNotThrow(()->{
			DocumentLoader loader = new CachingDocumentLoader();
			for(String id : CachingDocumentLoader.bundled.keySet()) {
				Document doc = loader.loadDocument(new URI(id), new DocumentLoaderOptions());
				Assertions.assertNotNull(doc);
			}
		});
	}

	@Test
	void testLocalDomainCachedDocument() {
		Assertions.assertDoesNotThrow(()->{
			Map<URI, String> localDomains = Map.of(new URI("http://example.org/"), "ob20");
			DocumentLoader loader = new CachingDocumentLoader(localDomains);
			URI uri = new URI("http://example.org/basic-assertion.json");
			Document doc = loader.loadDocument(uri, new DocumentLoaderOptions());
			Assertions.assertNotNull(doc);

			// assert the returned document is the same as the local resource
			URL resource = Resources.getResource("ob20/basic-assertion.json");
			JsonDocument resourceDocument = JsonDocument.of(resource.openStream());
			Assertions.assertEquals(resourceDocument.getJsonContent().toString(), doc.getJsonContent().toString());
		});
	}

	@Test
	void testStaticCachedDocumentKey() {
		Assertions.assertDoesNotThrow(()->{
			DocumentLoader loader = new CachingDocumentLoader();
			URI uri = new URI("https://www.w3.org/ns/did/v1");
			Document doc = loader.loadDocument(uri, new DocumentLoaderOptions());
			Assertions.assertNotNull(doc);
		});
	}
}