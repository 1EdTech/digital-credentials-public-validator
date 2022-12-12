package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertFatalCount;
import static org.oneedtech.inspect.test.Assertions.assertHasProbeID;
import static org.oneedtech.inspect.test.Assertions.assertInvalid;
import static org.oneedtech.inspect.test.Assertions.assertValid;
import static org.oneedtech.inspect.test.Assertions.assertWarning;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.util.TestOB20Inspector.TestBuilder;

public class OB20Tests {
	private static OB20Inspector validator;
	private static boolean verbose = true;

	@BeforeAll
	static void setup() throws URISyntaxException {
		TestBuilder builder = new TestBuilder();
		for (String localDomain : localDomains) {
			builder.add(new URI(localDomain), "ob20/assets");
		}
		validator = builder
			.set(Behavior.TEST_INCLUDE_SUCCESS, true)
			.set(Behavior.TEST_INCLUDE_WARNINGS, false)
			.set(Behavior.VALIDATOR_FAIL_FAST, true)
			.set(OB20Inspector.Behavior.ALLOW_LOCAL_REDIRECTION, true)
			.build();
	}

	@Test
	void testSimpleJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.JSON.SIMPLE_ASSERTION_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimplePNGPlainValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.PNG.SIMPLE_JSON_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleBadgeClassJsonValid() {
		// TODO: commented out due to lack of prerequisite tasks yet
		// assertDoesNotThrow(()->{
		// 	Report report = validator.run(Samples.OB20.JSON.SIMPLE_BADGECLASS.asFileResource());
		// 	if(verbose) PrintHelper.print(report, true);
		// 	assertValid(report);
		// });
	}

	@Test
	void testSimpleJsonInvalidContext() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.JSON.SIMPLE_ASSERTION_INVALID_CONTEXT_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertFatalCount(report, 1);
			assertHasProbeID(report, ContextPropertyProbe.ID, true);
		});
	}

	@Test
	void testSimpleJsonInvalidType() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.JSON.SIMPLE_ASSERTION_INVALID_TYPE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertFatalCount(report, 1);
			assertHasProbeID(report, TypePropertyProbe.ID, true);
		});
	}

	@Test
	void testSimpleJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.JWT.SIMPLE_JWT.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testLanguageInBadgeClass() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB20.JSON.SIMPLE_LANGUAGE_BADGECLASS.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
			// check than
		});
	}

	@Nested
	static class WarningTests {
		@BeforeAll
		static void setup() throws URISyntaxException {
			TestBuilder builder = new TestBuilder();
			for (String localDomain : localDomains) {
				builder.add(new URI(localDomain), "ob20/assets");
			}
			validator = builder
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)
				.set(Behavior.TEST_INCLUDE_WARNINGS, true)
				.set(Behavior.VALIDATOR_FAIL_FAST, true)
				.set(OB20Inspector.Behavior.ALLOW_LOCAL_REDIRECTION, true)
				.build();
		}

		@Test
		void testWarningRedirectionJsonValid() {
			assertDoesNotThrow(()->{
				Report report = validator.run(Samples.OB20.JSON.WARNING_REDIRECTION_ASSERTION_JSON.asFileResource());
				if(verbose) PrintHelper.print(report, true);
				assertWarning(report);
			});
		}

		@Test
		void testWarningIssuerNonHttps() {
			assertDoesNotThrow(()->{
				Report report = validator.run(Samples.OB20.JSON.WARNING_ISSUER_NON_HTTPS_JSON.asFileResource());
				if(verbose) PrintHelper.print(report, true);
				assertWarning(report);
			});
		}
	}

	private static final List<String> localDomains = List.of("https://www.example.org/", "https://example.org/", "http://example.org/");
}
