package org.oneedtech.inspect.vc.verification;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.google.common.io.Resources;

import foundation.identity.jsonld.ConfigurableDocumentLoader;

public class LDSecurityContexts {
    public static final URI JSONLD_CONTEXT_W3ID_SUITES_ED25519_2022_V1 = URI.create("https://w3id.org/security/data-integrity/v1");
    public static final URI JSONLD_CONTEXT_W3ID_VC_V2 = URI.create("https://www.w3.org/ns/credentials/v2");

    public static final Map<URI, JsonDocument> CONTEXTS;
    public static final DocumentLoader DOCUMENT_LOADER;

    static {

        try {

            CONTEXTS = new HashMap<>();

            CONTEXTS.putAll(info.weboftrust.ldsignatures.jsonld.LDSecurityContexts.CONTEXTS);

            CONTEXTS.put(JSONLD_CONTEXT_W3ID_SUITES_ED25519_2022_V1,
                    JsonDocument.of(MediaType.JSON_LD, Resources.getResource("contexts/data-integrity-v1.jsonld").openStream()));
            CONTEXTS.put(JSONLD_CONTEXT_W3ID_VC_V2,
                    JsonDocument.of(MediaType.JSON_LD, Resources.getResource("contexts/credentials-v2.jsonld").openStream()));

            for (Map.Entry<URI, JsonDocument> context : CONTEXTS.entrySet()) {
                context.getValue().setDocumentUrl(context.getKey());
            }
        } catch (JsonLdError | IOException ex) {

            throw new ExceptionInInitializerError(ex);
        }

        DOCUMENT_LOADER = new ConfigurableDocumentLoader(CONTEXTS);
    }
}
