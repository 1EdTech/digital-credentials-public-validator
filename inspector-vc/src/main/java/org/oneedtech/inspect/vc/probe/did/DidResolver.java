package org.oneedtech.inspect.vc.probe.did;

import java.net.URI;

import com.apicatalog.jsonld.loader.DocumentLoader;

public interface DidResolver {
    DidResolution resolve(URI did, DocumentLoader documentLoader) throws DidResolutionException;
}
