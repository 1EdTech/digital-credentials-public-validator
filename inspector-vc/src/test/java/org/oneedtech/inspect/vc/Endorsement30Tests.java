package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.assertFatalCount;
import static org.oneedtech.inspect.test.Assertions.assertHasProbeID;
import static org.oneedtech.inspect.test.Assertions.assertInvalid;
import static org.oneedtech.inspect.test.Assertions.assertValid;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;

public class Endorsement30Tests {
    private static EndorsementInspector validator; 
	private static boolean verbose = false;
	
	@BeforeAll 
	static void setup() {		
		validator = new EndorsementInspector.Builder()				
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)	
				.set(Behavior.VALIDATOR_FAIL_FAST, false)
				.build();	
	}

	@Test
	void testEndorsementWithoutErrors() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.ENDORSEMENT_VALID.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);
		});	
	}

	@Test
	void testEndorsementWithErrors() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.ENDORSEMENT_ERR_SCHEMA_STATUS_REFRESH.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertFatalCount(report, 1);
			// Parse probe fails because refresh points to invalid URL so nothing to parse
			assertHasProbeID(report, CredentialParseProbe.ID, true);
		});	
	}
}
