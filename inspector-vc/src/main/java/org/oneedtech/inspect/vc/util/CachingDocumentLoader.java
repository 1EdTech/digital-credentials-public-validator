package org.oneedtech.inspect.vc.util;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;

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

import foundation.identity.jsonld.ConfigurableDocumentLoader;

/**
 * A com.apicatalog DocumentLoader with a threadsafe static cache.
 *
 * @author mgylling
 */
public class CachingDocumentLoader extends ConfigurableDocumentLoader {


	public CachingDocumentLoader() {
		this(null);
	}

	public CachingDocumentLoader(Map<URI, String> localDomains) {
		super();
		setEnableHttp(true);
		setEnableHttps(true);
		setDefaultHttpLoader(new HttpLoader(localDomains));
	}

	@Override
	public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
		Document document = super.loadDocument(url, options);
		if (document == null) {
			logger.error("documentCache not able to load {}", url);
			throw new JsonLdError(JsonLdErrorCode.INVALID_REMOTE_CONTEXT);
		}
		return document;
	}

	public class HttpLoader implements DocumentLoader {
		final Map<URI, String> localDomains;

		public HttpLoader(Map<URI, String> localDomains) {
			this.localDomains = localDomains;
		}

		@Override
		public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
			try {
				// resolve url
				URI resolvedUrl = resolve(url);

				Tuple<String, DocumentLoaderOptions> tpl = new Tuple<>(resolvedUrl.toASCIIString(), options);

				return documentCache.get(tpl);
			} catch (Exception e) {
				logger.error("documentCache not able to load {}", url);
				throw new JsonLdError(JsonLdErrorCode.INVALID_REMOTE_CONTEXT, e.getMessage());
			}
		}

		/**
		 * Resolved given url. If the url is from one of local domain, a URL of the relative resource will be returned
		 * @throws URISyntaxException
		 */
		public URI resolve(URI url) throws URISyntaxException {
			if (localDomains != null) {
				URI base = url.resolve("/");
				if (localDomains.containsKey(base)) {
					URL resource = Resources.getResource(localDomains.get(base) + "/" + base.relativize(url).toString());
					return resource.toURI();
				}
			}
			return url;
		}
	}

	static final ImmutableMap<String, URL> bundled = ImmutableMap.<String, URL>builder()
			.put("https://purl.imsglobal.org/spec/clr/v2p0/context.json",Resources.getResource("contexts/clr-v2p0.json"))
			.put("https://purl.imsglobal.org/spec/ob/v3p0/context.json",Resources.getResource("contexts/ob-v3p0.json"))
			.put("https://purl.imsglobal.org/spec/ob/v3p0/extensions.json",Resources.getResource("contexts/ob-v3p0-extensions.json"))
			.put("https://www.w3.org/ns/did/v1", Resources.getResource("contexts/did-v1.jsonld"))
			.put("https://www.w3.org/ns/odrl.jsonld", Resources.getResource("contexts/odrl.jsonld"))
			.put("https://w3id.org/security/suites/ed25519-2020/v1",Resources.getResource("contexts/security-suites-ed25519-2020-v1.jsonld"))
			.put("https://www.w3.org/2018/credentials/v1", Resources.getResource("contexts/2018-credentials-v1.jsonld"))
			.put("https://w3id.org/security/v1", Resources.getResource("contexts/security-v1.jsonld"))
			.put("https://w3id.org/security/v2", Resources.getResource("contexts/security-v2.jsonld"))
			.put("https://w3id.org/security/v3", Resources.getResource("contexts/security-v3-unstable.jsonld"))
			.put("https://w3id.org/security/bbs/v1", Resources.getResource("contexts/security-bbs-v1.jsonld"))
			.put("https://w3id.org/security/suites/secp256k1-2019/v1", Resources.getResource("contexts/suites-secp256k1-2019.jsonld"))
			.put("https://w3id.org/security/suites/ed25519-2018/v1", Resources.getResource("contexts/suites-ed25519-2018.jsonld"))
			.put("https://w3id.org/security/suites/x25519-2019/v1", Resources.getResource("contexts/suites-x25519-2019.jsonld"))
			.put("https://w3id.org/security/suites/jws-2020/v1", Resources.getResource("contexts/suites-jws-2020.jsonld"))
			.put("https://openbadgespec.org/v2/context.json", Resources.getResource("contexts/ob-v2p0.json"))
			.put("https://w3id.org/openbadges/v2", Resources.getResource("contexts/obv2x.jsonld"))

			.build();

	static final LoadingCache<Tuple<String, DocumentLoaderOptions>, Document> documentCache = CacheBuilder.newBuilder()
			.initialCapacity(32).maximumSize(64).expireAfterAccess(Duration.ofHours(24))
			.build(new CacheLoader<Tuple<String, DocumentLoaderOptions>, Document>() {
				public Document load(final Tuple<String, DocumentLoaderOptions> id) throws Exception {
					try (InputStream is = bundled.containsKey(id.t1)
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
