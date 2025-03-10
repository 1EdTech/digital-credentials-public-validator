package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.vc.VerifiableCredential.Type.AchievementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.ClrCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.EndorsementCredential;
import static org.oneedtech.inspect.vc.VerifiableCredential.Type.VerifiablePresentation;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.resource.MimeType;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

/**
 * A wrapper object for a verifiable credential. This contains e.g. the origin resource and the
 * extracted JSON data plus any other stuff Probes need.
 *
 * @author mgylling
 */
public class VerifiableCredential extends Credential {
  final VerifiableCredential.Type credentialType;
  final VCVersion version;

  protected VerifiableCredential(
      Resource resource,
      JsonNode data,
      String jwt,
      Map<CredentialEnum, SchemaKey> schemas,
      VCVersion version) {
    super(ID, resource, data, jwt, schemas, version.issuanceDateField, version.expirationDateField);

    JsonNode typeNode = jsonData.get("type");
    this.credentialType = VerifiableCredential.Type.valueOf(typeNode);
    this.version = version;
  }

  public CredentialEnum getCredentialType() {
    return credentialType;
  }

  public ProofType getProofType() {
    return jwt == null ? ProofType.EMBEDDED : ProofType.EXTERNAL;
  }

  public VCVersion getVersion() {
    return version;
  }

  private static final Map<CredentialEnum, SchemaKey> schemas =
      new ImmutableMap.Builder<CredentialEnum, SchemaKey>()
          .put(AchievementCredential, Catalog.OB_30_ANY_ACHIEVEMENTCREDENTIAL_JSON)
          .put(ClrCredential, Catalog.CLR_20_ANY_CLRCREDENTIAL_JSON)
          .put(VerifiablePresentation, Catalog.CLR_20_ANY_CLRCREDENTIAL_JSON)
          .put(EndorsementCredential, Catalog.OB_30_ANY_ENDORSEMENTCREDENTIAL_JSON)
          .build();

  public static final String JSONLD_CONTEXT_W3C_CREDENTIALS_V2 =
      "https://www.w3.org/ns/credentials/v2";

  private static final Map<Set<VerifiableCredential.Type>, List<String>> contextMap =
      new ImmutableMap.Builder<Set<VerifiableCredential.Type>, List<String>>()
          .put(
              Set.of(Type.OpenBadgeCredential, AchievementCredential, EndorsementCredential),
              List.of(
                  JSONLD_CONTEXT_W3C_CREDENTIALS_V2,
                  "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"))
          .put(
              Set.of(ClrCredential),
              List.of(
                  JSONLD_CONTEXT_W3C_CREDENTIALS_V2,
                  "https://purl.imsglobal.org/spec/clr/v2p0/context-2.0.1.json",
                  "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"))
          .put(
              Set.of(Type.BitstringStatusListCredential),
              List.of(JSONLD_CONTEXT_W3C_CREDENTIALS_V2))
          .build();

  private static final Map<String, List<String>> contextAliasesMap =
      new ImmutableMap.Builder<String, List<String>>()
          .put(
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
              List.of(
                  "https://purl.imsglobal.org/spec/ob/v3p0/context/ob_v3p0.jsonld",
                  "https://purl.imsglobal.org/spec/ob/v3p0/context.json"))
          .put(
              "https://purl.imsglobal.org/spec/clr/v2p0/context-2.0.1.json",
              List.of("https://purl.imsglobal.org/spec/clr/v2p0/context.json"))
          .put(JSONLD_CONTEXT_W3C_CREDENTIALS_V2, List.of("https://www.w3.org/2018/credentials/v1"))
          .build();

  private static final Map<String, List<String>> contextVersioningPatternMap =
      new ImmutableMap.Builder<String, List<String>>()
          .put(
              "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
              List.of(
                  "https:\\/\\/purl\\.imsglobal\\.org\\/spec\\/ob\\/v3p0\\/context(-\\d+\\.\\d+\\.\\d+)*\\.json"))
          .put(
              "https://purl.imsglobal.org/spec/clr/v2p0/context-2.0.1.json",
              List.of(
                  "https:\\/\\/purl\\.imsglobal\\.org\\/spec\\/clr\\/v2p0\\/context(-\\d+\\.\\d+\\.\\d+)*\\.json"))
          .build();

  public enum Type implements CredentialEnum {
    AchievementCredential(Collections.emptyList()),
    OpenBadgeCredential(
        List.of(
            "OpenBadgeCredential",
            "AchievementCredential")), // treated as an alias of AchievementCredential
    ClrCredential(List.of("ClrCredential")),
    EndorsementCredential(List.of("EndorsementCredential")),
    VerifiablePresentation(Collections.emptyList()),
    VerifiableCredential(
        List.of("VerifiableCredential")), // this is an underspecifier in our context
    BitstringStatusListCredential(List.of("BitstringStatusListCredential")),
    Unknown(Collections.emptyList());

    private final List<String> allowedTypeValues;

    Type(List<String> allowedTypeValues) {
      this.allowedTypeValues = allowedTypeValues;
    }

    public static VerifiableCredential.Type valueOf(JsonNode typeNode) {
      if (typeNode != null) {
        List<String> values = JsonNodeUtil.asStringList(typeNode);
        for (String value : values) {
          if (value.equals("AchievementCredential") || value.equals("OpenBadgeCredential")) {
            return AchievementCredential;
          } else if (value.equals("ClrCredential")) {
            return ClrCredential;
          } else if (value.equals("VerifiablePresentation")) {
            return VerifiablePresentation;
          } else if (value.equals("EndorsementCredential")) {
            return EndorsementCredential;
          } else if (value.equals("BitstringStatusListCredential")) {
            return BitstringStatusListCredential;
          }
        }
      }
      return Unknown;
    }

    @Override
    public List<String> getRequiredTypeValues() {
      return List.of("VerifiableCredential");
    }

    @Override
    public List<String> getAllowedTypeValues() {
      return allowedTypeValues;
    }

    @Override
    public boolean isAllowedTypeValuesRequired() {
      return true;
    }

    @Override
    public List<String> getContextUris() {
      return contextMap.get(
          contextMap.keySet().stream()
              .filter(s -> s.contains(this))
              .findFirst()
              .orElseThrow(() -> new IllegalArgumentException(this.name() + " not recognized")));
    }

    @Override
    public Map<String, List<String>> getContextAliases() {
      return contextAliasesMap;
    }

    @Override
    public Map<String, List<String>> getContextVersionPatterns() {
      return contextVersioningPatternMap;
    }
  }

  public enum ProofType {
    EXTERNAL,
    EMBEDDED
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("super", super.toString())
        .add("credentialType", credentialType)
        .toString();
  }

  public static enum VCVersion {
    VCDMv2p0(ISSUED_ON_PROPERTY_NAME_V20, EXPIRES_AT_PROPERTY_NAME_V20),
    VCDMv1p1(ISSUED_ON_PROPERTY_NAME_V11, EXPIRES_AT_PROPERTY_NAME_V11);

    final String issuanceDateField;
    final String expirationDateField;

    VCVersion(String issuanceDateField, String expirationDateField) {
      this.issuanceDateField = issuanceDateField;
      this.expirationDateField = expirationDateField;
    }

    static VCVersion of(JsonNode context) {
      if (JsonNodeUtil.asNodeList(context).stream()
          .anyMatch(
              node -> node.isTextual() && node.asText().equals(JSONLD_CONTEXT_W3C_CREDENTIALS_V2)))
        return VCDMv2p0;

      return VCDMv1p1;
    }
  }

  public static class Builder extends Credential.Builder<VerifiableCredential> {
    @Override
    public VerifiableCredential build() {
      VCVersion version = VCVersion.of(getJsonData().get("@context"));

      return new VerifiableCredential(getResource(), getJsonData(), getJwt(), schemas, version);
    }
  }

  public static final String ID = VerifiableCredential.class.getCanonicalName();
  private static final String ISSUED_ON_PROPERTY_NAME_V11 = "issuanceDate";
  private static final String ISSUED_ON_PROPERTY_NAME_V20 = "validFrom";
  private static final String EXPIRES_AT_PROPERTY_NAME_V11 = "expirationDate";
  private static final String EXPIRES_AT_PROPERTY_NAME_V20 = "validUntil";
  public static final String JWT_NODE_NAME = "vc";
  public static final Boolean JWT_ALLOW_WHOLE_PAYLOAD = true;
  public static final List<MimeType> REFRESH_SERVICE_MIME_TYPES =
      List.of(MimeType.JSON, MimeType.JSON_LD, MimeType.TEXT_PLAIN);
}
