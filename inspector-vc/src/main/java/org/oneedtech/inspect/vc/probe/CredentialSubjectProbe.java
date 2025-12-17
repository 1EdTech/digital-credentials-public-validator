package org.oneedtech.inspect.vc.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.List;
import java.util.Optional;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * A Probe that checks credential subject specifics not capturable by schemata.
 *
 * @author mgylling
 */
public class CredentialSubjectProbe extends Probe<JsonNode> {

  /** Required type to be present. */
  private final String requiredType;

  private boolean achivementRequired;
  private boolean identifierRequired;

  public CredentialSubjectProbe(String requiredType) {
    this(requiredType, false, true);
  }

  public CredentialSubjectProbe(
      String requiredType, boolean achivementRequired, boolean identifierRequired) {
    super(ID);
    this.requiredType = requiredType;
    this.achivementRequired = achivementRequired;
    this.identifierRequired = identifierRequired;
  }

  @Override
  public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

    JsonNode subject = root.get("credentialSubject");
    if (subject == null)
      return notRun("no credentialSubject node found", ctx); // error reported by schema

    /** Check that type contains AchievementSubject */
    if (!JsonNodeUtil.asStringList(subject.get("type")).contains(requiredType)) {
      return error("credentialSubject is not of type \"" + requiredType + "\"", ctx);
    }

    /*
     * Check that we have either .id or .identifier populated
     */
    if (identifierRequired && idAndIdentifierEmpty(subject)) {
      return error("no id in credentialSubject", ctx);
    }

    /** if .identifier is provider, check its type */
    if (subject.hasNonNull("identifier")) {
      List<JsonNode> identifiers = JsonNodeUtil.asNodeList(subject.get("identifier"));
      for (JsonNode identifier : identifiers) {
        // check that type contains "IdentityObject"
        if (!JsonNodeUtil.asStringList(identifier.get("type")).contains("IdentityObject")) {
          return error("identifier in credentialSubject is not of type \"IdentityObject\"", ctx);
        }
      }
    }

    /*
     * Check results
     */
    if (subject.hasNonNull("result")) {
      List<JsonNode> results = JsonNodeUtil.asNodeList(subject.get("result"));
      for (JsonNode result : results) {
        // check that type contains "Result"
        if (!JsonNodeUtil.asStringList(result.get("type")).contains("Result")) {
          return error("result in credentialSubject is not of type \"Result\"", ctx);
        }
      }
    }

    /*
     * Check achievement result description
     */
    if (subject.hasNonNull("achievement")) {
      Optional<ReportItems> achievementResult = checkAchievement(subject.get("achievement"), ctx);
      if (achievementResult.isPresent()) {
        return achievementResult.get();
      }

    } else if (achivementRequired) {
      return error("missing required achievement in credentialSubject", ctx);
    }

    /** Check that source type contains "Profile" */
    if (subject.hasNonNull("source")) {
      JsonNode source = subject.get("source");
      // check that type contains "Profile"
      if (!JsonNodeUtil.asStringList(source.get("type")).contains("Profile")) {
        return error("source in credentialSubject is not of type \"Profile\"", ctx);
      }
    }
    return success(ctx);
  }

  protected Optional<ReportItems> checkAchievement(JsonNode achievement, RunContext ctx) {
    if (achievement.hasNonNull("resultDescription")) {
      List<JsonNode> resultDescriptions =
          JsonNodeUtil.asNodeList(achievement.get("resultDescription"));
      for (JsonNode resultDescription : resultDescriptions) {
        // check that type contains "ResultDescription"
        if (!JsonNodeUtil.asStringList(resultDescription.get("type"))
            .contains("ResultDescription")) {
          return Optional.of(
              error(
                  "resultDescription in achievement of credentialSubject is not of type"
                      + " \"ResultDescription\"",
                  ctx));
        }
      }
    }
    // criteria must have id or narrative
    JsonNode criteria = achievement.get("criteria");
    if (!criteria.hasNonNull("id") && !criteria.hasNonNull("narrative")) {
      return Optional.of(
          error("criteria in achievement of credentialSubject must have id or narrative", ctx));
    }
    return Optional.empty();
  }

  private boolean idAndIdentifierEmpty(JsonNode root) {
    JsonNode id = root.get("id");
    if (id != null && id.textValue().strip().length() > 0) return false;

    List<JsonNode> identifiers = JsonNodeUtil.asNodeList(root.get("identifier"));
    if (identifiers == null || identifiers.size() > 0) return false;

    return true;
  }

  public static final String ID = CredentialSubjectProbe.class.getSimpleName();
}
