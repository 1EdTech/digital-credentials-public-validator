package org.oneedtech.inspect.vc.probe;

import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.json.JsonSchemaProbe;
import org.oneedtech.inspect.core.report.ReportItem;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.vc.VerifiableCredential;

public class JsonSchemasProbe extends Probe<VerifiableCredential> {
  private SchemaKey key;

  public JsonSchemasProbe(SchemaKey key) {
    this.key = key;
  }

  @Override
  public ReportItems run(VerifiableCredential cred, RunContext ctx) throws Exception {

    // main run
    JsonSchemaProbe jsonSchemaProbe = new JsonSchemaProbe(key);
    ReportItems report = jsonSchemaProbe.run(cred.getJson(), ctx);

    if (report.asBoolean()) {
      return report;
    }

    // aliases run
    if (key.getAliases().isPresent()) {
      for (SchemaKey alias : key.getAliases().get()) {
        jsonSchemaProbe = new JsonSchemaProbe(alias);
        ReportItems newReport = jsonSchemaProbe.run(cred.getJson(), ctx);

        if (newReport.asBoolean()) {
          // return old errors as warnings
          return new ReportItems(
              StreamSupport.stream(report.spliterator(), false)
                  .map(
                      item ->
                          new ReportItem.Builder(this)
                              .msg(
                                  "JSON-LD schema validation succeed. However, Plain JSON schema"
                                      + " validation failed, so it could have an impact when working with"
                                      + " plain JSON platforms. Error:"
                                      + item.getMessage())
                              .loc(item.getLocation())
                              .outcome(Outcome.WARNING)
                              .build())
                  .collect(Collectors.toUnmodifiableList()));
        }
      }

    }

    return report;
  }
}
