package org.oneedtech.inspect.vc.jsonld.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.validation.Validation;

public class JsonLDValidationProbe extends Probe<String> {

    public JsonLDValidationProbe() {
        super();
    }

    @Override
    public ReportItems run(String json, RunContext ctx) throws Exception {
        JsonLDObject jsonLd = JsonLDObject.fromJson(new StringReader(json));
        jsonLd.setDocumentLoader(new CachingDocumentLoader());
        try {
            Validation.validate(jsonLd);
            return success(this, ctx);
        } catch (Exception e) {
            return fatal("Error while validation JSON LD object: " + e.getMessage(), ctx);
        }
    }

}
