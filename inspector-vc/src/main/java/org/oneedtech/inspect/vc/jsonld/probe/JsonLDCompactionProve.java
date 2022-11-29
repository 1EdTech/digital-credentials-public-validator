package org.oneedtech.inspect.vc.jsonld.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.api.CompactionApi;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;

import jakarta.json.JsonObject;


public class JsonLDCompactionProve extends Probe<Credential> {
    private final String context;

    public JsonLDCompactionProve(String context) {
        super(ID);
        this.context = context;
    }

    @Override
    public ReportItems run(Credential crd, RunContext ctx) throws Exception {
      try {
          // compact JSON
          JsonDocument jsonDocument = JsonDocument.of(new StringReader(crd.getJson().toString()));
          CompactionApi compactApi = JsonLd.compact(jsonDocument, context);
          compactApi.options(new JsonLdOptions((DocumentLoader) ctx.get(Key.JSON_DOCUMENT_LOADER)));

          JsonObject compactedObject = compactApi.get();
          ctx.addGeneratedObject(new JsonLdGeneratedObject(getId(crd), compactedObject.toString()));

          // Handle mismatch between URL node source and declared ID.
          if (compactedObject.get("id") != null && crd.getResource().getID() != null
            && !compactedObject.get("id").toString().equals(crd.getResource().getID())) {
              // TODO: a new fetch of the JSON document at id is required
              return warning("Node fetched from source " + crd.getResource().getID() + " declared its id as " + compactedObject.get("id").toString(), ctx);
          }

          return success(this, ctx);
      } catch (Exception e) {
        return fatal("Error while parsing credential: " + e.getMessage(), ctx);
      }
    }

    public static String getId(Credential crd) {
      return "json-ld-compact:" + crd.getResource().getID();
    }

	public static final String ID = JsonLDCompactionProve.class.getSimpleName();
}
