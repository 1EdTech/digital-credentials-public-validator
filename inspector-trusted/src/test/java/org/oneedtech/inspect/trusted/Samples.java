package org.oneedtech.inspect.trusted;

import org.oneedtech.inspect.test.Sample;

public class Samples {
  public static final class TRUSTED {
    public static final Sample VALID = new Sample("trusted/valid.json", true);
    public static final Sample ERR_REQUIRED_CONTEXTS =
        new Sample("trusted/err-required-contexts.json", false);
    public static final Sample ERR_CONTEXT_ORDER =
        new Sample("trusted/err-context-order.json", false);
    public static final Sample ERR_SCHEMA_MISSING = new Sample("trusted/err-schema-missing.json", false);
    public static final Sample ERR_SCHEMA_VIOLATION =
        new Sample("trusted/err-schema-violation.json", false);
    public static final Sample ERR_ALIGNMENT = new Sample("trusted/err-alignment.json", false);
    public static final Sample ERR_ACHIEVED_LEVEL = new Sample("trusted/err-achieved-level.json", false);
    public static final Sample WARN_NO_CREDITS_NO_EXTENSIONS =
        new Sample("trusted/warn-no-credits-no-extensions.json", false);
  }
}
