package org.oneedtech.inspect.vc.resource;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.UriResource;

public class OB20JsonLDUriResourceFactory implements UriResourceFactory {

    @Override
    public UriResource of(String uri) throws URISyntaxException {
        return new UriResource(new URI(uri), ResourceType.JSON, List.of(ResourceType.JSON_LD, ResourceType.JSON));
    }

    @Override
    public UriResource of(URI uri) throws URISyntaxException {
        return new UriResource(uri, ResourceType.JSON, List.of(ResourceType.JSON_LD, ResourceType.JSON));
    }
}
