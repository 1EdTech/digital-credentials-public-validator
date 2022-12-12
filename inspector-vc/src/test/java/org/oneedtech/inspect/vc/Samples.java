package org.oneedtech.inspect.vc;

import org.oneedtech.inspect.test.Sample;

public class Samples {
	public static final class OB30 {
		public static final class SVG {
			public final static Sample SIMPLE_JSON_SVG = new Sample("ob30/simple-json.svg", true);
			public final static Sample SIMPLE_JWT_SVG = new Sample("ob30/simple-jwt.svg", true);
		}
		public static final class JSON {
			public final static Sample COMPLETE_JSON = new Sample("ob30/complete.json", false);
			public final static Sample SIMPLE_JSON = new Sample("ob30/simple.json", true);
			public final static Sample SIMPLE_DID_METHOD_JSON = new Sample("ob30/simple-did-method.json", true);
			public final static Sample SIMPLE_JSON_NOPROOF = new Sample("ob30/simple-noproof.json", false);
			public final static Sample SIMPLE_JSON_UNKNOWN_TYPE = new Sample("ob30/simple-err-type.json", false);
			public final static Sample SIMPLE_JSON_PROOF_METHOD_ERROR = new Sample("ob30/simple-err-proof-method.json", false);
			public final static Sample SIMPLE_JSON_PROOF_METHOD_NO_SCHEME_ERROR = new Sample("ob30/simple-err-proof-method-no-scheme.json", false);
			public final static Sample SIMPLE_JSON_PROOF_METHOD_UNKNOWN_SCHEME_ERROR = new Sample("ob30/simple-err-proof-method-unknown-scheme.json", false);
			public final static Sample SIMPLE_JSON_PROOF_METHOD_UNKNOWN_DID_METHOD_ERROR = new Sample("ob30/simple-err-proof-method-unknown-did-method.json", false);
			public final static Sample SIMPLE_JSON_PROOF_VALUE_ERROR = new Sample("ob30/simple-err-proof-value.json", false);
			public final static Sample SIMPLE_JSON_EXPIRED = new Sample("ob30/simple-err-expired.json", false);
			public final static Sample SIMPLE_JSON_ISSUED = new Sample("ob30/simple-err-issued.json", false);
			public final static Sample SIMPLE_JSON_ISSUER = new Sample("ob30/simple-err-issuer.json", false);
			public final static Sample SIMPLE_JSON_ERR_CONTEXT = new Sample("ob30/simple-err-context.json", false);
		}
		public static final class PNG {
			public final static Sample SIMPLE_JWT_PNG = new Sample("ob30/simple-jwt.png", true);
			public final static Sample SIMPLE_JSON_PNG = new Sample("ob30/simple-json.png", true);
		}
		public static final class JWT {
			public final static Sample SIMPLE_JWT = new Sample("ob30/simple.jwt", true);
		}
	}

	public static final class CLR20 {
		public static final class JSON {
			public final static Sample SIMPLE_JSON = new Sample("clr20/simple.json", true);
			public final static Sample SIMPLE_JSON_NOPROOF = new Sample("clr20/simple-noproof.json", true);
			public final static Sample SIMPLE_JWT = new Sample("clr20/simple.jwt", true);
		}
	}

	public static final class OB20 {
		public static final class JSON {
			//  original: test_verify: test_verify_function
			public final static Sample SIMPLE_ASSERTION_JSON = new Sample("ob20/basic-assertion.json", true);
			public final static Sample SIMPLE_ASSERTION_INVALID_CONTEXT_JSON = new Sample("ob20/basic-assertion-invalid-context.json", true);
			public final static Sample SIMPLE_ASSERTION_INVALID_TYPE_JSON = new Sample("ob20/basic-assertion-invalid-type.json", true);
			// original:
			public final static Sample SIMPLE_ASSERTION_ISSUER_WITHOUT_PUBLIC_KEY_JSON = new Sample("ob20/basic-assertion-no-public-key.json", true);
			// original: test_graph: test_verify_with_redirection
			public final static Sample WARNING_REDIRECTION_ASSERTION_JSON = new Sample("ob20/warning-with-redirection.json", true);
			// original: test_validation: test_issuer_warn_on_non_https_id
			public final static Sample WARNING_ISSUER_NON_HTTPS_JSON = new Sample("ob20/warning-issuer-non-http.json", true);
			// original: test_validation: test_can_input_badgeclass
			public final static Sample SIMPLE_BADGECLASS = new Sample("ob20/assets/badgeclass1.json", true);
			// original: test_validation: test_validate_compacted_iri_value
			public final static Sample ISSUER_COMPACTIRI_VALIDATION = new Sample("ob20/issuer-compact-iri-validation.json", true);
			// original: validate_language: validate_language_prop_basic
			public final static Sample SIMPLE_LANGUAGE_BADGECLASS = new Sample("ob20/badge-class-with-language.json", true);
			// original: test_validation: test_validate_in_context_string_type
			public final static Sample RDF_VALIDATION_VALID_BADGE_CLASS = new Sample("ob20/rdf-validation/valid-badge-class.json", true);
			public final static Sample RDF_VALIDATION_VALID_ISSUER_EXTENSION_CLASS = new Sample("ob20/rdf-validation/valid-issuer-extension.json", true);
			public final static Sample RDF_VALIDATION_VALID_ALIGNMENT_OBJECT = new Sample("ob20/rdf-validation/valid-alignment-object.json", true);
			public final static Sample RDF_VALIDATION_VALID_EXTERNAL_CLASS = new Sample("ob20/rdf-validation/valid-cool-class.json", true);
			public final static Sample RDF_VALIDATION_INVALID_CLASS = new Sample("ob20/rdf-validation/invalid-class.json", true);
			public final static Sample RDF_VALIDATION_INVALID_EMPTY_CLASS = new Sample("ob20/rdf-validation/invalid-empty-type.json", true);
			public final static Sample RDF_VALIDATION_INVALID_ELEM_CLASS = new Sample("ob20/rdf-validation/invalid-one-invalid-class.json", true);
			public final static Sample RDF_VALIDATION_INVALID_ISSUER_TYPE = new Sample("ob20/rdf-validation/badge-class-invalid-issuer-type.json", true);
			public final static Sample RDF_VALIDATION_VALID_EMPTY_CRITERIA_TYPE = new Sample("ob20/rdf-validation/valid-badge-class-empty-criteria-type.json", true);
			// otiginal: test_validation: test_hosted_verification_object_in_assertion
			public final static Sample ISSUER_WITH_ALLOWED_ORIGINS = new Sample("ob20/basic-assertion-with-allowed-origins.json", true);
			public final static Sample ISSUER_WITH_ALLOWED_ORIGINS_VALID_STARTSWITH = new Sample("ob20/basic-assertion-with-allowed-origins-valid-starts-with.json", true);
			public final static Sample ISSUER_WITH_ALLOWED_ORIGINS_INVALID_STARTSWITH = new Sample("ob20/basic-assertion-with-allowed-origins-invalid-starts-with.json", true);
			public final static Sample ISSUER_WITH_ALLOWED_ORIGINS_VALID_MULTIPLE_STARTSWITH = new Sample("ob20/basic-assertion-with-allowed-origins-valid-multiple-starts-with.json", true);
			public final static Sample ISSUER_WITH_ALLOWED_ORIGINS_INVALID_MULTIPLE_STARTSWITH = new Sample("ob20/basic-assertion-with-allowed-origins-invalid-multiple-starts-with.json", true);
			// original: test_validation: test_assertion_not_expired
			public final static Sample SIMPLE_EXPIRED_ASSERTION_JSON = new Sample("ob20/basic-assertion-expired.json", true);
			// original: test_validation: test_assertion_not_expires_before_issue
			public final static Sample SIMPLE_EXPIRED_BEFORE_ISSUED_ASSERTION_JSON = new Sample("ob20/basic-assertion-expired-before-issued.json", true);
			// original: test_validation: test_assertion_not_issued_in_future
			public final static Sample SIMPLE_FUTURE_ASSERTION_JSON = new Sample("ob20/basic-assertion-in-future.json", true);
		}

		public static final class PNG {
			// original: test_verify: test_verify_of_baked_image
			public final static Sample SIMPLE_JSON_PNG = new Sample("ob20/simple-badge.png", true);
		}

		public static final class JWT {
			public final static Sample SIMPLE_JWT = new Sample("ob20/simple.jwt", true);
		}
	}
}
