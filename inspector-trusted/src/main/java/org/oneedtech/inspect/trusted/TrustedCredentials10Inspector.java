package org.oneedtech.inspect.trusted;

import java.util.List;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.trusted.probe.AchievedLevelProbe;
import org.oneedtech.inspect.trusted.probe.AlignmentFrameworkProbe;
import org.oneedtech.inspect.trusted.probe.CreditsProbe;
import org.oneedtech.inspect.trusted.probe.ExtensionContextProbe;
import org.oneedtech.inspect.trusted.probe.TrustedSchemaProbe;
import org.oneedtech.inspect.trusted.schema.TrustedCatalog;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.util.version.Version;
import org.oneedtech.inspect.vc.OB30Inspector;
import org.oneedtech.inspect.vc.VerifiableCredential;

/**
 * A verifier for TrustEd Credentials 1.0, a profile of Open Badges 3.0.
 *
 * <p>Runs the full Open Badges 3.0 verification, then the TrustEd profile probes. The profile
 * probes run whenever the credential could be parsed, even if OB 3.0 verification reported errors.
 */
public class TrustedCredentials10Inspector extends OB30Inspector {

  static {
    // make the bundled TrustEd Schema resolvable before any schema validation runs
    TrustedCatalog.init();
  }

  protected TrustedCredentials10Inspector(TrustedCredentials10Inspector.Builder builder) {
    super(builder);
  }

  /** The profile probes, in the order they run after OB 3.0 verification. */
  static List<Probe<VerifiableCredential>> profileProbes() {
    return List.of(
        new TrustedSchemaProbe(),
        new AlignmentFrameworkProbe(),
        new AchievedLevelProbe(),
        new CreditsProbe(),
        ExtensionContextProbe.assessment(),
        ExtensionContextProbe.accreditation());
  }

  public static class Builder extends OB30Inspector.Builder {
    public Builder() {
      super();
      profileProbes().forEach(this::add);
    }

    @Override
    public TrustedCredentials10Inspector build() {
      set(TRUSTED_CREDENTIALS_10);
      set(ResourceType.OPENBADGE);
      return new TrustedCredentials10Inspector(this);
    }
  }

  public static final Specification TRUSTED_CREDENTIALS_10 =
      new Specification("obtc", "ob", Version.of("1.0"), "TrustEd Credentials");
}
