package org.oneedtech.inspect.vc.jsonld.probe;

import java.io.StringReader;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;

import com.apicatalog.jsonld.JsonLd;
import com.apicatalog.jsonld.JsonLdOptions;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.loader.DocumentLoader;

import jakarta.json.JsonObject;

/**
 * JSON-LD compaction probe for Open Badges 2.0
 * Maps to "JSONLD_COMPACT_DATA" task in python implementation
 * @author xaracil
 */
public class JsonLDCompactionProbe extends Probe<Credential> {
    private final String context;

    public JsonLDCompactionProbe(String context) {
        super(ID);
        this.context = context;
    }

    @Override
    public ReportItems run(Credential crd, RunContext ctx) throws Exception {
      try {
          // compact JSON
          JsonDocument jsonDocument = JsonDocument.of(new StringReader(crd.getJson().toString()));
          JsonObject compactedObject = JsonLd.compact(jsonDocument, context)
            .options(new JsonLdOptions((DocumentLoader) ctx.get(Key.JSON_DOCUMENT_LOADER)))
            .get();

          ctx.addGeneratedObject(new JsonLdGeneratedObject(getId(crd), compactedObject.toString()));

          // Handle mismatch between URL node source and declared ID.
          if (compactedObject.get("id") != null && crd.getResource().getID() != null
            && !compactedObject.get("id").toString().equals(crd.getResource().getID())) {
              // TODO: a new fetch of the JSON document at id is required
              return warning("Node fetched from source " + crd.getResource().getID() + " declared its id as " + compactedObject.get("id").toString(), ctx);
          }

          return success(this, ctx);
      } catch (Exception e) {
        return fatal("Error while compacting JSON-LD: " + crd.getJson() + ". Caused by: " + e.getMessage(), ctx);
      }
    }

    public static String getId(Credential crd) {
      return getId(crd.getResource());
    }

    public static String getId(Resource resource) {
      return getId(resource.getID());
    }
    public static String getId(String id) {
      return "json-ld-compact:" + id;
    }

	public static final String ID = JsonLDCompactionProbe.class.getSimpleName();
}
