package org.oneedtech.inspect.trusted.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.oneedtech.inspect.trusted.probe.ProbeTestSupport.run;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.Outcome;

public class TrustedSchemaProbeTests {
  private static final String URI =
      "https://purl.1edtech.org/spec/ob/v3p0/obtc/v1p0/schema/json/ob_v3p0_obtc_v1p0_achievementcredential-jsonschema1.json";

  private Outcome run(String credentialSchema) throws Exception {
    return ProbeTestSupport.run(new TrustedSchemaProbe(), "{'credentialSchema':" + credentialSchema + "}");
  }

  @Test
  void declaredAmongOthersPasses() throws Exception {
    assertEquals(
        Outcome.VALID,
        run("[{'id':'https://example.org/other.json','type':'1EdTechJsonSchemaValidator2019'},"
            + "{'id':'" + URI + "','type':'1EdTechJsonSchemaValidator2019'}]"));
  }

  @Test
  void singleObjectPasses() throws Exception {
    assertEquals(Outcome.VALID, run("{'id':'" + URI + "','type':'1EdTechJsonSchemaValidator2019'}"));
  }

  @Test
  void missingCredentialSchemaFails() throws Exception {
    assertEquals(Outcome.ERROR, ProbeTestSupport.run(new TrustedSchemaProbe(), "{}"));
  }

  @Test
  void otherSchemaOnlyFails() throws Exception {
    assertEquals(
        Outcome.ERROR,
        run("[{'id':'https://example.org/other.json','type':'1EdTechJsonSchemaValidator2019'}]"));
  }

  @Test
  void wrongTypeFails() throws Exception {
    assertEquals(Outcome.ERROR, run("[{'id':'" + URI + "','type':'JsonSchema'}]"));
  }
}
