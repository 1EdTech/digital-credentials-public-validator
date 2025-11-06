package org.oneedtech.inspect.vc.jsonld.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;

import com.apicatalog.jsonld.loader.DocumentLoader;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.validation.Validation;

public class JsonLDValidationProbe extends Probe<String> {

    DocumentLoader documentLoader;

    public JsonLDValidationProbe() {
        this(null);
    }

    public JsonLDValidationProbe(DocumentLoader documentLoader) {
        super();
        this.documentLoader = documentLoader;
    }

    @Override
    public ReportItems run(String json, RunContext ctx) throws Exception {
        JsonLDObject jsonLd = JsonLDObject.fromJson(new StringReader(json));
        jsonLd.setDocumentLoader(documentLoader);
        try {
            Validation.validate(jsonLd);
            return success(this, ctx);
        } catch (Exception e) {
            return error("Error while validation JSON LD object: " + e.getMessage(), ctx);
        }
    }

	public static final String ID = JsonLDValidationProbe.class.getSimpleName();
}
