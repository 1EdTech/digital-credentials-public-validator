package org.oneedtech.inspect.clr;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertValid;
import static org.oneedtech.inspect.test.Assertions.assertWarning;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;

public class CLR20Tests {
    private static CLR20Inspector validator;
	private static boolean verbose = true;

	@BeforeAll
	static void setup() {
		validator = new CLR20Inspector.Builder()
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)
				.set(Behavior.VALIDATOR_FAIL_FAST, false)
				.inject(Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL, "http://dev.uniresolver.io/1.0/identifiers/")
				.build();
	}

    @Test
	void testSimpleJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.CLR20.JSON.SIMPLE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

	@Test
	void testSimpleV1JsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.CLR20.JSON.SIMPLE_V1_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			// warning due to outdated context versions
			assertWarning(report);
		});
	}

	// commented out due that https://western.riverwell.k12.or.us/ is not accessible
	// @Test
 	// void testComplexJsonValid() {
	// 	assertDoesNotThrow(()->{
	// 		Report report = validator.run(Samples.CLR20.JSON.COMPLEX_JSON.asFileResource());
	// 		if(verbose) PrintHelper.print(report, true);
	// 		assertValid(report);
	// 	});
	// }

	@Disabled
	@Test
	void testSimpleJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.CLR20.JSON.SIMPLE_JWT.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}
}
