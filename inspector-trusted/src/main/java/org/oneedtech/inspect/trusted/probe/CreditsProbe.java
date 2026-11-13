package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;

/**
 * Checks that duration information is included, via {@code credentialSubject.creditsEarned} and/or
 * {@code credentialSubject.achievement.creditsAvailable}. Missing both is a warning (SHOULD).
 */
public class CreditsProbe extends Probe<VerifiableCredential> {

  public CreditsProbe() {
    super(ID, TITLE);
  }

  @Override
  public ReportItems run(VerifiableCredential credential, RunContext ctx) throws Exception {
    JsonNode subject = credential.getJson().get("credentialSubject");
    boolean earned = subject != null && subject.hasNonNull("creditsEarned");
    JsonNode achievement = subject == null ? null : subject.get("achievement");
    boolean available = achievement != null && achievement.hasNonNull("creditsAvailable");

    if (earned || available) {
      return success("Duration information is included", ctx);
    }
    return warning(
        "Duration information should be included using credentialSubject.creditsEarned"
            + " and/or credentialSubject.achievement.creditsAvailable",
        ctx);
  }

  public static final String ID = CreditsProbe.class.getSimpleName();
  public static final String TITLE = "Duration information (credits)";
}
