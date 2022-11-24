package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertValid;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.util.TestOB20Inspector.TestBuilder;

public class OB20Tests {
	private static OB20Inspector validator;
	private static boolean verbose = true;

	@BeforeAll
	static void setup() throws URISyntaxException {
		validator = new TestBuilder()
			.add(new URI("https://www.example.org/"), "ob20/assets")
			.set(Behavior.TEST_INCLUDE_SUCCESS, true)
			.set(Behavior.TEST_INCLUDE_WARNINGS, true)
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
}
