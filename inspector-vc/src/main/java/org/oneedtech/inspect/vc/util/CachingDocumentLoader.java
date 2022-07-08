package org.oneedtech.inspect.vc.util;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.time.Duration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.oneedtech.inspect.util.code.Tuple;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.Resources;

/**
 * A com.apicatalog DocumentLoader with a threadsafe static cache.  
 * @author mgylling
 */
public class CachingDocumentLoader implements DocumentLoader {
		
	@Override
	public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {		
		Tuple<String, DocumentLoaderOptions> tpl = new Tuple<>(url.toASCIIString(), options);
		try {
			return documentCache.get(tpl);	
		} catch (Exception e) {
			logger.error("documentCache not able to load {}", url);
			throw new JsonLdError(JsonLdErrorCode.INVALID_REMOTE_CONTEXT, e.getMessage());
		} 						
	}
	
	static final ImmutableMap<String, URL> bundled = ImmutableMap.<String, URL>builder()			  
			  .put("https://www.w3.org/ns/did/v1", Resources.getResource("contexts/did-v1.jsonld"))
			  .put("https://www.w3.org/ns/odrl.jsonld", Resources.getResource("contexts/odrl.jsonld"))
			  .put("https://w3id.org/security/suites/ed25519-2020/v1", Resources.getResource("contexts/security-suites-ed25519-2020-v1.jsonld"))
			  .put("https://www.w3.org/2018/credentials/v1", Resources.getResource("contexts/2018-credentials-v1.jsonld"))
			  .put("https://imsglobal.github.io/openbadges-specification/context.json", Resources.getResource("contexts/obv3.jsonld"))			  
			  .build();
	
	static final LoadingCache<Tuple<String, DocumentLoaderOptions>, Document> documentCache = CacheBuilder.newBuilder()
			.initialCapacity(32)
			.maximumSize(64)
			.expireAfterAccess(Duration.ofHours(24))
			.build(new CacheLoader<Tuple<String, DocumentLoaderOptions>, Document>() {
				public Document load(final Tuple<String, DocumentLoaderOptions> id) throws Exception {									
					try (InputStream is = bundled.keySet().contains(id.t1) 
							? bundled.get(id.t1).openStream() 
							: new URI(id.t1).toURL().openStream();) {
			            return JsonDocument.of(is);																								
					} 
				}
			});

	public static void reset() {
		documentCache.invalidateAll();
	}
	
	private static final Logger logger = LogManager.getLogger();
}
