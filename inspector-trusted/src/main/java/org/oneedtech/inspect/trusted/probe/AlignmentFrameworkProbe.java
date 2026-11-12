package org.oneedtech.inspect.trusted.probe;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * Checks that alignments reference an external skills framework via URI.
 *
 * <p>The asserted achievement must have at least one alignment. Every alignment anywhere under
 * {@code credentialSubject} (excluding embedded endorsement credentials, which are validated on
 * their own) must have an absolute http(s) {@code targetUrl} and a {@code targetFramework}.
 */
public class AlignmentFrameworkProbe extends Probe<VerifiableCredential> {

  private static final List<String> SKIPPED_PROPERTIES = List.of("endorsement", "endorsementJwt");

  public AlignmentFrameworkProbe() {
    super(ID, TITLE);
  }

  @Override
  public ReportItems run(VerifiableCredential credential, RunContext ctx) throws Exception {
    JsonNode subject = credential.getJson().get("credentialSubject");
    if (subject == null || subject.isNull()) {
      return error("credentialSubject is missing", ctx);
    }

    List<String> problems = new ArrayList<>();
    JsonNode achievement = subject.get("achievement");
    JsonNode achievementAlignment = achievement == null ? null : achievement.get("alignment");
    if (achievementAlignment == null
        || achievementAlignment.isNull()
        || (achievementAlignment.isArray() && achievementAlignment.size() == 0)) {
      problems.add("credentialSubject.achievement must have at least one alignment");
    }

    collect(subject, "credentialSubject", problems);

    if (!problems.isEmpty()) {
      return error(String.join("; ", problems), ctx);
    }
    return success("All alignments reference an external framework via URI", ctx);
  }

  private void collect(JsonNode node, String path, List<String> problems) {
    if (node.isArray()) {
      for (int i = 0; i < node.size(); i++) {
        collect(node.get(i), path + "[" + i + "]", problems);
      }
    } else if (node.isObject()) {
      Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
      while (fields.hasNext()) {
        Map.Entry<String, JsonNode> field = fields.next();
        String name = field.getKey();
        if (SKIPPED_PROPERTIES.contains(name)) continue;
        String fieldPath = path + "." + name;
        if ("alignment".equals(name)) {
          List<JsonNode> alignments = JsonNodeUtil.asNodeList(field.getValue());
          for (int i = 0; i < alignments.size(); i++) {
            check(alignments.get(i), fieldPath + "[" + i + "]", problems);
          }
        }
        collect(field.getValue(), fieldPath, problems);
      }
    }
  }

  private void check(JsonNode alignment, String path, List<String> problems) {
    JsonNode targetUrl = alignment.get("targetUrl");
    if (targetUrl == null || !targetUrl.isTextual() || !isHttpUri(targetUrl.textValue())) {
      problems.add(path + ".targetUrl must be an absolute http(s) URI of the framework item");
    }
    JsonNode targetFramework = alignment.get("targetFramework");
    if (targetFramework == null
        || !targetFramework.isTextual()
        || targetFramework.textValue().isBlank()) {
      problems.add(path + ".targetFramework must name the external framework");
    }
  }

  static boolean isHttpUri(String value) {
    try {
      URI uri = new URI(value.strip());
      String scheme = uri.getScheme();
      return uri.isAbsolute()
          && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
          && uri.getHost() != null;
    } catch (Exception e) {
      return false;
    }
  }

  public static final String ID = AlignmentFrameworkProbe.class.getSimpleName();
  public static final String TITLE = "Alignments reference an external skills framework";
}
