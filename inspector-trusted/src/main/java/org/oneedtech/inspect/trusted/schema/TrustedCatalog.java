package org.oneedtech.inspect.trusted.schema;

import static org.oneedtech.inspect.schema.SchemaType.JSON;

import org.oneedtech.inspect.schema.Catalog;
import org.oneedtech.inspect.schema.JsonSchemaMapper;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;

/**
 * Locally bundled JSON schemas for TrustEd Credentials 1.0.
 *
 * <p>The canonical schema URI is not yet resolvable online, so the schema is served from the
 * classpath. Loading this class registers it with {@link JsonSchemaMapper} and {@link
 * InlineJsonSchemaProbe}.
 */
public class TrustedCatalog extends Catalog {

  /** The TrustEd Schema: the AchievementCredential schema of the TrustEd Credentials 1.0 profile. */
  public static final SchemaKey TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON =
      new SchemaKey.Builder()
          .type(JSON)
          .uri(
              "https://purl.imsglobal.org/spec/ob/v3p0/obtc/v1p0/schema/json/ob_v3p0_obtc_v1p0_achievementcredential-jsonschema1.json")
          .path(
              "catalog/purl.imsglobal.org/spec/ob/v3p0/obtc/v1p0/schema/json/ob_v3p0_obtc_v1p0_achievementcredential-jsonschema1.json")
          .build();

  static {
    JsonSchemaMapper.register(TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON);
    InlineJsonSchemaProbe.registerLocalSchema(TRUSTED_ACHIEVEMENT_CREDENTIAL_JSON);
  }

  /** Forces class initialization, and therefore schema registration. */
  public static void init() {}
}
