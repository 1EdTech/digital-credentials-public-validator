package org.oneedtech.inspect.trusted;

import org.oneedtech.inspect.test.Sample;

public class Samples {
  public static final class TRUSTED {
    public static final Sample VALID = new Sample("trusted/valid.json", true);
    /**
     * valid.json without result.resultDate: resultDate is required by the TrustEd Schema but not
     * defined by any JSON-LD context, so it is removed to isolate the extension contexts.
     */
    public static final Sample JSONLD_EXTENSION_CONTEXTS =
        new Sample("trusted/jsonld-extension-contexts.json", false);
    public static final Sample ERR_SCHEMA_MISSING = new Sample("trusted/err-schema-missing.json", false);
    public static final Sample ERR_SCHEMA_VIOLATION =
        new Sample("trusted/err-schema-violation.json", false);
    public static final Sample ERR_ALIGNMENT = new Sample("trusted/err-alignment.json", false);
    public static final Sample ERR_ACHIEVED_LEVEL = new Sample("trusted/err-achieved-level.json", false);
    public static final Sample WARN_NO_CREDITS_NO_EXTENSIONS =
        new Sample("trusted/warn-no-credits-no-extensions.json", false);
  }
}
