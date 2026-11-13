package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.trusted.Samples;
import org.oneedtech.inspect.trusted.TrustedCredentials10Inspector;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.VerifiableCredential;

final class ProbeTestSupport {
  private static final ObjectMapper mapper = new ObjectMapper();

  private ProbeTestSupport() {}

  /** Runs the probe on a credential built from the given JSON and returns its outcome. */
  static Outcome run(Probe<VerifiableCredential> probe, String json) throws Exception {
    ObjectNode root = (ObjectNode) mapper.readTree(json.replace('\'', '"'));
    // the credential builder needs a recognizable credential; probes under test ignore these
    if (!root.has("@context")) {
      root.putArray("@context")
          .add("https://www.w3.org/ns/credentials/v2")
          .add("https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json");
    }
    root.putArray("type").add("VerifiableCredential").add("OpenBadgeCredential");
    Resource resource = Samples.TRUSTED.VALID.asFileResource(ResourceType.JSON);
    VerifiableCredential credential =
        new VerifiableCredential.Builder().resource(resource).jsonData(root).build();
    RunContext ctx =
        new RunContext.Builder()
            .put(new TrustedCredentials10Inspector.Builder().build())
            .put(resource)
            .build();
    return probe.run(credential, ctx).getOutcome();
  }
}
