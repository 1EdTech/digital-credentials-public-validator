package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Checks that a recommended JSON-LD context is listed anywhere in the credential's {@code @context},
 * matching by exact string. A missing context is a warning. Required contexts are checked, in
 * order, by the OB 3.0 context property check (see {@code TrustedCredentialType}).
 */
public class RecommendedContextProbe extends Probe<VerifiableCredential> {

  private final String contextName;
  private final String contextUri;

  private RecommendedContextProbe(String id, String title, String contextName, String contextUri) {
    super(id, title);
    this.contextName = contextName;
    this.contextUri = contextUri;
  }

  /** Open Badges Assessment Extension context. */
  public static RecommendedContextProbe assessment() {
    return new RecommendedContextProbe(
        ASSESSMENT_ID,
        "Open Badges Assessment Extension context",
        "Open Badges Assessment Extension",
        ASSESSMENT_CONTEXT);
  }

  /** Open Badges Issuer Accreditation Extension context. */
  public static RecommendedContextProbe accreditation() {
    return new RecommendedContextProbe(
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
          return success("@context includes the " + contextName + " context", ctx);
        }
      }
    }
    return warning(
        "@context should include the " + contextName + " context (" + contextUri + ")", ctx);
  }

  public static final String ASSESSMENT_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-assessment/v2p0/context";
  public static final String ACCREDITATION_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-accred/v2p0/context";
  public static final String ASSESSMENT_ID = "AssessmentExtensionContextProbe";
  public static final String ACCREDITATION_ID = "AccreditationExtensionContextProbe";
}
