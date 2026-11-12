package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Warns when an expected extension JSON-LD context is not listed in the credential's {@code
 * @context}. Matching is by exact string.
 */
public class ExtensionContextProbe extends Probe<VerifiableCredential> {

  private final String extensionName;
  private final String contextUri;

  private ExtensionContextProbe(String id, String title, String extensionName, String contextUri) {
    super(id, title);
    this.extensionName = extensionName;
    this.contextUri = contextUri;
  }

  /** Open Badges Assessment Extension context. */
  public static ExtensionContextProbe assessment() {
    return new ExtensionContextProbe(
        ASSESSMENT_ID,
        "Open Badges Assessment Extension context",
        "Open Badges Assessment Extension",
        ASSESSMENT_CONTEXT);
  }

  /** Open Badges Issuer Accreditation Extension context. */
  public static ExtensionContextProbe accreditation() {
    return new ExtensionContextProbe(
        ACCREDITATION_ID,
        "Open Badges Issuer Accreditation Extension context",
        "Open Badges Issuer Accreditation Extension",
        ACCREDITATION_CONTEXT);
  }

  @Override
  public ReportItems run(VerifiableCredential credential, RunContext ctx) throws Exception {
    JsonNode context = credential.getJson().get("@context");
    if (context != null) {
      for (JsonNode entry : JsonNodeUtil.asNodeList(context)) {
        if (entry.isTextual() && contextUri.equals(entry.textValue())) {
          return success("@context includes the " + extensionName + " context", ctx);
        }
      }
    }
    return warning(
        "@context does not include the " + extensionName + " context (" + contextUri + ")", ctx);
  }

  public static final String ASSESSMENT_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-assessment/v2p0/context";
  public static final String ACCREDITATION_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-accred/v2p0/context";
  public static final String ASSESSMENT_ID = "AssessmentExtensionContextProbe";
  public static final String ACCREDITATION_ID = "AccreditationExtensionContextProbe";
}
