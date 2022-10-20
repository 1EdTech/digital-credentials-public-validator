package org.oneedtech.inspect.vc.util;

import java.net.URI;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;

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
	void testStaticCachedDocumentKey() {
		Assertions.assertDoesNotThrow(()->{
			DocumentLoader loader = new CachingDocumentLoader();
			URI uri = new URI("https://www.w3.org/ns/did/v1");
			Document doc = loader.loadDocument(uri, new DocumentLoaderOptions());
			Assertions.assertNotNull(doc);
		});
	}	
}