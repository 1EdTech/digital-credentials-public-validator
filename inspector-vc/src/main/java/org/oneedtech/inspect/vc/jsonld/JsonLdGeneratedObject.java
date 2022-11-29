package org.oneedtech.inspect.vc.jsonld;

import org.oneedtech.inspect.core.probe.GeneratedObject;

public class JsonLdGeneratedObject extends GeneratedObject {
    private String json;

    public JsonLdGeneratedObject(String json) {
        this(ID, json);
    }

    public JsonLdGeneratedObject(String id, String json) {
        super(id, GeneratedObject.Type.INTERNAL);
        this.json = json;
    }

    public String getJson() {
        return json;
    }

    public static final String ID = JsonLdGeneratedObject.class.getCanonicalName();
}
