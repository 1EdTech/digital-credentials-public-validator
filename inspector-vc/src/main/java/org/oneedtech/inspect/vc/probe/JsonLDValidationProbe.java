package org.oneedtech.inspect.vc.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.JsonLdGeneratedObject;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.validation.Validation;

public class JsonLDValidationProbe extends Probe<Credential> {
    private final JsonLdGeneratedObject jsonLdObject;

    public JsonLDValidationProbe(JsonLdGeneratedObject jsonLdObject) {
        super();
        this.jsonLdObject = jsonLdObject;
    }

    @Override
    public ReportItems run(Credential crd, RunContext ctx) throws Exception {
        JsonLDObject jsonLd = JsonLDObject.fromJson(new StringReader(jsonLdObject.getJson()));
        try {
            Validation.validate(jsonLd);
            return success(this, ctx);
        } catch (Exception e) {
            return fatal("Error while validation JSON LD object: " + e.getMessage(), ctx);
        }
    }

}
