package org.oneedtech.inspect.trusted;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItem;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.trusted.probe.AchievedLevelProbe;
import org.oneedtech.inspect.trusted.probe.AlignmentFrameworkProbe;
import org.oneedtech.inspect.trusted.probe.CreditsProbe;
import org.oneedtech.inspect.trusted.probe.RecommendedContextProbe;
import org.oneedtech.inspect.trusted.probe.TrustedSchemaProbe;
import org.oneedtech.inspect.trusted.schema.TrustedCatalog;
import org.oneedtech.inspect.test.Sample;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDValidationProbe;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;

/**
 * Fixtures carry a placeholder proof, so OB 3.0 proof verification always fails. Tests therefore
 * assert on the outcome of specific probes rather than on overall validity.
 */
public class TrustedCredentials10InspectorTests {
  private static Inspector validator;
  private static final boolean verbose = true;
  /** Generator of the OB 3.0 context check when run against the TrustEd credential type. */
  private static final String CONTEXT_CHECK =
      ContextPropertyProbe.ID + "|" + TrustedCredentialType.INSTANCE + "|@context";

  @BeforeAll
  static void setup() {
    validator =
        new TrustedCredentials10Inspector.Builder()
            .set(Behavior.TEST_INCLUDE_SUCCESS, true)
            .inject(
                Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL,
                "http://dev.uniresolver.io/1.0/identifiers/")
            .build();
  }

  private static Report run(Sample sample) throws Exception {
    Report report = validator.run(sample.asFileResource());
    if (verbose) PrintHelper.print(report, true);
    return report;
  }

  private static List<Outcome> outcomes(Report report, String probeId) {
    List<Outcome> outcomes = new ArrayList<>();
    for (ReportItem item : report) {
      if (item.getGenerator().equals(probeId)) outcomes.add(item.getOutcome());
    }
    return outcomes;
  }

  private static void assertOutcome(Report report, String probeId, Outcome expected) {
    List<Outcome> outcomes = outcomes(report, probeId);
    assertEquals(List.of(expected), outcomes, probeId + " outcomes");
  }

  private static void assertNoFailures(Report report, String probeId) {
    List<Outcome> failures =
        outcomes(report, probeId).stream()
            .filter(o -> o != Outcome.VALID)
            .collect(Collectors.toList());
    assertTrue(failures.isEmpty(), probeId + " reported " + failures);
  }

  @Test
  void validCredentialPassesAllProfileProbes() throws Exception {
    Report report = run(Samples.TRUSTED.VALID);
    assertOutcome(report, CONTEXT_CHECK, Outcome.VALID);
    assertOutcome(report, TrustedSchemaProbe.ID, Outcome.VALID);
    assertOutcome(report, AlignmentFrameworkProbe.ID, Outcome.VALID);
    assertOutcome(report, AchievedLevelProbe.ID, Outcome.VALID);
    assertOutcome(report, CreditsProbe.ID, Outcome.VALID);
    assertOutcome(report, RecommendedContextProbe.ASSESSMENT_ID, Outcome.VALID);
    assertOutcome(report, RecommendedContextProbe.ACCREDITATION_ID, Outcome.VALID);
  }

  @Test
  void validCredentialConformsToBundledTrustedSchema() throws Exception {
    Report report = run(Samples.TRUSTED.VALID);
    String schemaUri = TrustedCatalog.TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON.getCanonicalURI();
    boolean validated = false;
    for (ReportItem item : report) {
      boolean aboutTrustedSchema =
          item.getGenerator().contains(schemaUri) || item.getMessage().contains(schemaUri);
      if (!aboutTrustedSchema && !item.getGenerator().equals(InlineJsonSchemaProbe.ID)) continue;
      assertEquals(Outcome.VALID, item.getOutcome(), item.getGenerator() + ": " + item.getMessage());
      validated |= aboutTrustedSchema;
    }
    assertTrue(validated, "credential was not validated against the TrustEd Schema");
  }

  @Test
  void trustedSchemaViolationIsReported() throws Exception {
    // awardedDate is optional in OB 3.0 but required by the TrustEd Schema
    Report report = run(Samples.TRUSTED.ERR_SCHEMA_VIOLATION);
    String schemaUri = TrustedCatalog.TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON.getCanonicalURI();
    boolean reported = false;
    for (ReportItem item : report) {
      if (item.getGenerator().contains(schemaUri) && item.getOutcome() != Outcome.VALID) {
        reported = true;
      }
    }
    assertTrue(reported, "TrustEd Schema violation was not reported");
  }

  @Test
  void validCredentialPassesJsonLd() throws Exception {
    // the TrustEd context defines resultDate; the extension contexts must not clash with OB 3.0
    Report report = run(Samples.TRUSTED.VALID);
    assertNoFailures(report, JsonLDValidationProbe.ID);
  }

  @Test
  void missingRequiredContextsAreErrors() throws Exception {
    Report report = run(Samples.TRUSTED.ERR_REQUIRED_CONTEXTS);
    assertOutcome(report, CONTEXT_CHECK, Outcome.ERROR);
    // a context error does not stop the profile probes
    assertOutcome(report, TrustedSchemaProbe.ID, Outcome.VALID);
  }

  @Test
  void misorderedRequiredContextsAreErrors() throws Exception {
    Report report = run(Samples.TRUSTED.ERR_CONTEXT_ORDER);
    assertOutcome(report, CONTEXT_CHECK, Outcome.ERROR);
  }

  @Test
  void missingSchemaIsError() throws Exception {
    Report report = run(Samples.TRUSTED.ERR_SCHEMA_MISSING);
    assertOutcome(report, TrustedSchemaProbe.ID, Outcome.ERROR);
  }

  @Test
  void invalidAlignmentsAreError() throws Exception {
    Report report = run(Samples.TRUSTED.ERR_ALIGNMENT);
    assertOutcome(report, AlignmentFrameworkProbe.ID, Outcome.ERROR);
  }

  @Test
  void missingAchievedLevelIsError() throws Exception {
    Report report = run(Samples.TRUSTED.ERR_ACHIEVED_LEVEL);
    assertOutcome(report, AchievedLevelProbe.ID, Outcome.ERROR);
  }

  @Test
  void missingCreditsAndExtensionContextsAreWarnings() throws Exception {
    Report report = run(Samples.TRUSTED.WARN_NO_CREDITS_NO_EXTENSIONS);
    assertOutcome(report, CreditsProbe.ID, Outcome.WARNING);
    assertOutcome(report, RecommendedContextProbe.ASSESSMENT_ID, Outcome.WARNING);
    assertOutcome(report, RecommendedContextProbe.ACCREDITATION_ID, Outcome.WARNING);
  }
}
