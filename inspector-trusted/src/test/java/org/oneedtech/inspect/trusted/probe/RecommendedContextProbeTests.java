package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.oneedtech.inspect.trusted.probe.ProbeTestSupport.run;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class RecommendedContextProbeTests {
  private static final String BASE =
      "'https://www.w3.org/ns/credentials/v2',"
          + "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'";
  private static final String ASSESSMENT =
      "'https://purl.imsglobal.org/spec/ob-assessment/v2p0/context'";
  private static final String ACCREDITATION =
      "'https://purl.imsglobal.org/spec/ob-accred/v2p0/context'";

  @Test
  void presentContextsPass() throws Exception {
    String all = "{'@context':[" + BASE + "," + ASSESSMENT + "," + ACCREDITATION + "]}";
    assertEquals(Outcome.VALID, run(RecommendedContextProbe.assessment(), all));
    assertEquals(Outcome.VALID, run(RecommendedContextProbe.accreditation(), all));
  }

  @Test
  void positionDoesNotMatter() throws Exception {
    String reordered = "{'@context':[" + ACCREDITATION + "," + ASSESSMENT + "," + BASE + "]}";
    assertEquals(Outcome.VALID, run(RecommendedContextProbe.assessment(), reordered));
    assertEquals(Outcome.VALID, run(RecommendedContextProbe.accreditation(), reordered));
  }

  @Test
  void missingContextsWarn() throws Exception {
    String none = "{'@context':[" + BASE + "]}";
    assertEquals(Outcome.WARNING, run(RecommendedContextProbe.assessment(), none));
    assertEquals(Outcome.WARNING, run(RecommendedContextProbe.accreditation(), none));
  }

  @Test
  void matchingIsExact() throws Exception {
    String similar =
        "{'@context':[" + BASE + ",'https://purl.imsglobal.org/spec/ob-assessment/v2p0/context/']}";
    assertEquals(Outcome.WARNING, run(RecommendedContextProbe.assessment(), similar));
  }
}
