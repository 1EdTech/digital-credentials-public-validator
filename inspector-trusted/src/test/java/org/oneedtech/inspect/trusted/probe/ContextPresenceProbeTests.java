package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.oneedtech.inspect.trusted.probe.ProbeTestSupport.run;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class ContextPresenceProbeTests {
  private static final String BASE =
      "'https://www.w3.org/ns/credentials/v2',"
          + "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json'";
  private static final String ALL =
      "{'@context':[" + BASE + ","
          + "'https://purl.imsglobal.org/spec/ob/v3p0/extensions.json',"
          + "'https://purl.1edtech.org/spec/ob/v3p0/obtc/v1p0/context.json',"
          + "'https://purl.imsglobal.org/spec/ob-assessment/v2p0/context',"
          + "'https://purl.imsglobal.org/spec/ob-accred/v2p0/context']}";
  private static final String NONE = "{'@context':[" + BASE + "]}";

  @Test
  void presentContextsPass() throws Exception {
    assertEquals(Outcome.VALID, run(ContextPresenceProbe.trusted(), ALL));
    assertEquals(Outcome.VALID, run(ContextPresenceProbe.obExtensions(), ALL));
    assertEquals(Outcome.VALID, run(ContextPresenceProbe.assessment(), ALL));
    assertEquals(Outcome.VALID, run(ContextPresenceProbe.accreditation(), ALL));
  }

  @Test
  void missingRequiredContextsAreErrors() throws Exception {
    assertEquals(Outcome.ERROR, run(ContextPresenceProbe.trusted(), NONE));
    assertEquals(Outcome.ERROR, run(ContextPresenceProbe.obExtensions(), NONE));
  }

  @Test
  void missingRecommendedContextsWarn() throws Exception {
    assertEquals(Outcome.WARNING, run(ContextPresenceProbe.assessment(), NONE));
    assertEquals(Outcome.WARNING, run(ContextPresenceProbe.accreditation(), NONE));
  }

  @Test
  void matchingIsExact() throws Exception {
    String similar =
        "{'@context':[" + BASE + ",'https://purl.1edtech.org/spec/ob/v3p0/obtc/v1p0/context.json/']}";
    assertEquals(Outcome.ERROR, run(ContextPresenceProbe.trusted(), similar));
  }
}
