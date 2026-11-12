package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Checks that a JSON-LD context is listed in the credential's {@code @context}, matching by exact
 * string. A missing required context is an error; a missing recommended one is a warning.
 */
public class ContextPresenceProbe extends Probe<VerifiableCredential> {

  private final String contextName;
  private final String contextUri;
  private final boolean required;

  private ContextPresenceProbe(
      String id, String title, String contextName, String contextUri, boolean required) {
    super(id, title);
    this.contextName = contextName;
    this.contextUri = contextUri;
    this.required = required;
  }

  /** TrustEd Credentials 1.0 context (required). */
  public static ContextPresenceProbe trusted() {
    return new ContextPresenceProbe(
        TRUSTED_ID,
        "TrustEd Credentials 1.0 context",
        "TrustEd Credentials 1.0",
        TRUSTED_CONTEXT,
        true);
  }

  /** Open Badges 3.0 extensions context (required). */
  public static ContextPresenceProbe obExtensions() {
    return new ContextPresenceProbe(
        OB_EXTENSIONS_ID,
        "Open Badges 3.0 extensions context",
        "Open Badges 3.0 extensions",
        OB_EXTENSIONS_CONTEXT,
        true);
  }

  /** Open Badges Assessment Extension context (recommended). */
  public static ContextPresenceProbe assessment() {
    return new ContextPresenceProbe(
        ASSESSMENT_ID,
        "Open Badges Assessment Extension context",
        "Open Badges Assessment Extension",
        ASSESSMENT_CONTEXT,
        false);
  }

  /** Open Badges Issuer Accreditation Extension context (recommended). */
  public static ContextPresenceProbe accreditation() {
    return new ContextPresenceProbe(
        ACCREDITATION_ID,
        "Open Badges Issuer Accreditation Extension context",
        "Open Badges Issuer Accreditation Extension",
        ACCREDITATION_CONTEXT,
        false);
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
    String message =
        "@context " + (required ? "must" : "should") + " include the " + contextName
            + " context (" + contextUri + ")";
    return required ? error(message, ctx) : warning(message, ctx);
  }

  public static final String TRUSTED_CONTEXT =
      "https://purl.1edtech.org/spec/ob/v3p0/obtc/v1p0/context.json";
  public static final String OB_EXTENSIONS_CONTEXT =
      "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json";
  public static final String ASSESSMENT_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-assessment/v2p0/context";
  public static final String ACCREDITATION_CONTEXT =
      "https://purl.imsglobal.org/spec/ob-accred/v2p0/context";
  public static final String TRUSTED_ID = "TrustedContextProbe";
  public static final String OB_EXTENSIONS_ID = "ObExtensionsContextProbe";
  public static final String ASSESSMENT_ID = "AssessmentExtensionContextProbe";
  public static final String ACCREDITATION_ID = "AccreditationExtensionContextProbe";
}
