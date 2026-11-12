package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.trusted.schema.TrustedCatalog;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Checks that the credential declares the TrustEd Schema in {@code credentialSchema}, with the
 * {@code 1EdTechJsonSchemaValidator2019} type so that the credential is validated against it.
 *
 * <p>The validation itself is performed by the OB 3.0 inline schema probe.
 */
public class TrustedSchemaProbe extends Probe<VerifiableCredential> {

  static final String VALIDATOR_TYPE = "1EdTechJsonSchemaValidator2019";

  public TrustedSchemaProbe() {
    super(ID, TITLE);
  }

  @Override
  public ReportItems run(VerifiableCredential credential, RunContext ctx) throws Exception {
    String schemaUri = TrustedCatalog.TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON.getCanonicalURI();
    JsonNode credentialSchema = credential.getJson().get("credentialSchema");
    if (credentialSchema == null || credentialSchema.isNull()) {
      return error("credentialSchema is missing; it must include " + schemaUri, ctx);
    }

    boolean declaredWithOtherType = false;
    for (JsonNode entry : JsonNodeUtil.asNodeList(credentialSchema)) {
      JsonNode id = entry.get("id");
      if (id == null || !schemaUri.equals(id.asText().strip())) continue;
      JsonNode type = entry.get("type");
      if (type != null && VALIDATOR_TYPE.equals(type.asText())) {
        return success("credentialSchema includes the TrustEd Credentials 1.0 schema", ctx);
      }
      declaredWithOtherType = true;
    }

    if (declaredWithOtherType) {
      return error(
          "credentialSchema entry for " + schemaUri + " must have type " + VALIDATOR_TYPE, ctx);
    }
    return error("credentialSchema does not include " + schemaUri, ctx);
  }

  public static final String ID = TrustedSchemaProbe.class.getSimpleName();
  public static final String TITLE = "TrustEd Credentials 1.0 schema declaration";
}
