package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertValid;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.util.resource.ResourceType;

public class BitstringStatusListCredentialInspectorTest {
	private static BitstringStatusListCredentialInspector validator;
	private static boolean verbose = true;

	@BeforeAll
	static void setup() {
		validator = new BitstringStatusListCredentialInspector.Builder()
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)
				.set(Behavior.VALIDATOR_FAIL_FAST, true)
				.build();
	}

	@Test
	void testSimpleJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.BSL.SIMPLE_JSON.asFileResource(ResourceType.JSON));
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});
	}

}
