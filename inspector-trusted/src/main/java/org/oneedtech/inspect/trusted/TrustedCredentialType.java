package org.oneedtech.inspect.trusted;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.oneedtech.inspect.vc.Credential.CredentialEnum;
import org.oneedtech.inspect.vc.VerifiableCredential;

/**
 * The {@code @context} and {@code type} expectations of a TrustEd Credential: those of an Open
 * Badges 3.0 credential, with the OB 3.0 extensions and TrustEd Credentials 1.0 contexts required
 * right after the OB 3.0 context. The added contexts match by exact string.
 */
public final class TrustedCredentialType implements CredentialEnum {

  public static final String OB_EXTENSIONS_CONTEXT =
      "https://purl.imsglobal.org/spec/ob/v3p0/extensions.json";
  public static final String TRUSTED_CONTEXT =
      "https://purl.1edtech.org/spec/ob/v3p0/obtc/v1p0/context.json";

  private static final CredentialEnum BASE = VerifiableCredential.Type.OpenBadgeCredential;

  // declared after the constants it reads, so static initialization sees them
  public static final TrustedCredentialType INSTANCE = new TrustedCredentialType();

  private final List<String> contextUris;

  private TrustedCredentialType() {
    List<String> uris = new ArrayList<>(BASE.getContextUris());
    uris.add(OB_EXTENSIONS_CONTEXT);
    uris.add(TRUSTED_CONTEXT);
    this.contextUris = Collections.unmodifiableList(uris);
  }

  @Override
  public List<String> getContextUris() {
    return contextUris;
  }

  @Override
  public List<String> getRequiredTypeValues() {
    return BASE.getRequiredTypeValues();
  }

  @Override
  public List<String> getAllowedTypeValues() {
    return BASE.getAllowedTypeValues();
  }

  @Override
  public boolean isAllowedTypeValuesRequired() {
    return BASE.isAllowedTypeValuesRequired();
  }

  @Override
  public List<String> getSupportedEmbeddedProofTypes() {
    return BASE.getSupportedEmbeddedProofTypes();
  }

  @Override
  public Map<String, List<String>> getContextAliases() {
    return BASE.getContextAliases();
  }

  @Override
  public Map<String, List<String>> getContextVersionPatterns() {
    return BASE.getContextVersionPatterns();
  }

  @Override
  public String toString() {
    return "TrustEdCredential";
  }
}
