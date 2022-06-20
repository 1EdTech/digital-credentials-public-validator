package org.oneedtech.inspect.vc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.test.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.test.PrintHelper;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;


public class OB30Tests {
	private static OB30Inspector validator; 
	private static boolean verbose = true;
	
	@BeforeAll 
	static void setup() {		
		validator = new OB30Inspector.Builder()				
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)				
				.build();		
	}
	
	@Test
	void testSimpleJsonValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);			
		});	
	}
	
	@Disabled
	@Test
	void testSimplePNGPlainValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.PNG.SIMPLE_JSON_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);			
		});	
	}
	
	@Disabled
	@Test
	void testSimplePNGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.PNG.SIMPLE_JWT_PNG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);			
		});	
	}

	@Test
	void testSimpleJsonSVGPlainValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SVG.SIMPLE_JSON_SVG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);			
		});	
	}
	
	@Disabled
	@Test
	void testSimpleJsonSVGJWTValid() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.SVG.SIMPLE_JWT_SVG.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertValid(report);			
		});	
	}

	@Test
	void testSimpleJsonInvalidUnknownType() {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.SIMPLE_JSON_UNKNOWN_TYPE.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
		});	
	}
		
	@Test
	void testCompleteJsonInvalidInlineSchemaRef() throws Exception {
		assertDoesNotThrow(()->{
			Report report = validator.run(Samples.OB30.JSON.COMPLETE_JSON.asFileResource());
			if(verbose) PrintHelper.print(report, true);
			assertInvalid(report);
			assertErrorCount(report, 1);
			assertHasProbeID(report, InlineJsonSchemaProbe.ID, true);									
		});	
	}

}
