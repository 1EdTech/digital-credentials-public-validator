package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.oneedtech.inspect.trusted.probe.ProbeTestSupport.run;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class ExtensionContextProbeTests {
  private static final String BOTH =
      "{'@context':['https://www.w3.org/ns/credentials/v2',"
          + "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',"
          + "'https://purl.imsglobal.org/spec/ob-assessment/v2p0/context',"
          + "'https://purl.imsglobal.org/spec/ob-accred/v2p0/context']}";

  @Test
  void presentContextsPass() throws Exception {
    assertEquals(Outcome.VALID, run(ExtensionContextProbe.assessment(), BOTH));
    assertEquals(Outcome.VALID, run(ExtensionContextProbe.accreditation(), BOTH));
  }

  @Test
  void missingContextsWarn() throws Exception {
    String none =
        "{'@context':['https://www.w3.org/ns/credentials/v2',"
            + "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json']}";
    assertEquals(Outcome.WARNING, run(ExtensionContextProbe.assessment(), none));
    assertEquals(Outcome.WARNING, run(ExtensionContextProbe.accreditation(), none));
  }

  @Test
  void matchingIsExact() throws Exception {
    String similar =
        "{'@context':['https://www.w3.org/ns/credentials/v2',"
            + "'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',"
            + "'https://purl.imsglobal.org/spec/ob-assessment/v2p0/context/']}";
    assertEquals(Outcome.WARNING, run(ExtensionContextProbe.assessment(), similar));
  }
}
