package org.oneedtech.inspect.oneroster;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.oneedtech.inspect.core.probe.Outcome.ERROR;
import static org.oneedtech.inspect.core.probe.Outcome.WARNING;
import static org.oneedtech.inspect.oneroster.OneRoster11Inspector.TransactionKeys.ACADEMIC_SESSIONS_GET_200;
import static org.oneedtech.inspect.oneroster.Samples.OR11.AS678;
import static org.oneedtech.inspect.oneroster.Samples.OR11.AS678I;
import static org.oneedtech.inspect.oneroster.Samples.OR11.D198;
import static org.oneedtech.inspect.testutil.Assertions.*;
import static org.oneedtech.inspect.testutil.Sample.fieldsToList;
import static org.oneedtech.inspect.util.net.HttpMethod.GET;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.Inspector.Behavior;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.context.JsonContext;
import org.oneedtech.inspect.core.probe.json.JsonPredicates;
import org.oneedtech.inspect.core.probe.json.JsonPropertyPredicateProbe;
import org.oneedtech.inspect.core.probe.json.JsonPropertyPresentProbe;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.testutil.Sample;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.StringResource;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

class OneRoster11Tests {
	private static OneRoster11Inspector inspector; 
	
	@BeforeAll 
	static void setup() throws Exception {		
		inspector = new OneRoster11Inspector.Builder().build();		
	}
	
	@Test
	void testSampleAS678() throws Exception {				
		StringResource json = new StringResource(AS678.asString(), "myID", GET, "/academicSessions", 200);				
		assertValid(inspector.run(json));
	}
	
	@Test
	void testSampleD198() throws Exception {
		//this yields > 200k error messages						
		StringResource json = new StringResource(D198.asString(), "myID", GET, "/demographics", 200);		
		Report report = inspector.run(json);
		assertInvalid(report);
		assertTrue(report.size(true) > 200000);			
		assertHasOnlyErrors(report, true);						
		//all from the same test
		assertEquals(1, report.asMap().keySet().size());
	}
		
	@Test
	void testSampleAS678I() throws Exception {								
		StringResource sr = new StringResource(AS678I.asString(), "myID", GET, "/academicSessions", 200);		
		Report report = inspector.run(sr);
		//System.err.println(report.toString(true));
		assertInvalid(report);
		assertErrorCount(report, 4);
	}
		
	@Test
	void testInvalidEndpoint() throws Exception {		
		//a valid academicSessions payload returned from another endpoint		
		StringResource sr = new StringResource(AS678.asString(), "myID", GET, "/users", 200);		
		Report report = inspector.run(sr);
		assertInvalid(report);
	}
	
	@Test
	void testNonExistingEndpoint() throws Exception {		
		//a non-existing endpoint		
		StringResource sr = new StringResource(AS678.asString(), "myID", GET, "/foo", 200);		
		Report report = inspector.run(sr);
		//print(report, true);
		assertNotRun(report);	
		assertNotRunCount(report, 1);	
	}
	
	@Test
	void testMalformedJson() throws Exception {		
		//a non-existing endpoint		
		StringResource sr = new StringResource("not a json string", "myID", GET, "/users", 200);		
		Report report = inspector.run(sr);
		//print(report, true);
		assertInvalid(report);
		assertFatalCount(report, 1);
			
	}
	
	@Test
	void testAllSamples() throws Exception {
		List<Sample> input = fieldsToList(Samples.OR11.class.getFields());
				
		for(Sample sample : input) {
			String body = sample.asString(); 
			String endPoint = sample.getTransactionKey().orElseThrow().getEndpoint();
			int code = sample.getTransactionKey().orElseThrow().getStatusCodes()[0];			
			Resource resource = new StringResource(body, "myID", GET, endPoint, code);
						
			Report report = inspector.run(resource);
			
			if(sample.isValid()) {
				assertValid(report);	
			} else {
				assertInvalid(report);
			}
		}
	}
	
	@Test
	void testAddParametrizedTests() throws Exception {
		//add parametrized tests from core lib and a custom
		String payload = AS678.asString();						
		StringResource rsrc = new StringResource(payload, "myID", GET, "/academicSessions", 200);
		
		OneRoster11Inspector validator = new OneRoster11Inspector.Builder()	
				//.add(new PrintStreamListener(System.out, true))
				.set(Behavior.TEST_INCLUDE_SUCCESS, true)
				//.remove(predicate)
				//.set(OneRoster11Inspector.TransactionKeys.ACADEMIC_SESSIONS_GET_200)
				
				//this one succeeds
				.add(ACADEMIC_SESSIONS_GET_200, new JsonPropertyPresentProbe("$.academicSessions[*]", "status", 
						 "You really should include status", WARNING))
				//this one warns
				.add(ACADEMIC_SESSIONS_GET_200, new JsonPropertyPresentProbe("$.academicSessions[*]", "foo", 
						 "Think again about including foo", WARNING))				
				//this one errors
				.add(ACADEMIC_SESSIONS_GET_200, new JsonPropertyPredicateProbe("$.academicSessions[*].status", 
						 JsonPredicates.valueEquals("foo"), 
						 "The status field does not have expected value 'foo'", ERROR))
				//this one warns
				.add(ACADEMIC_SESSIONS_GET_200, new JsonPropertyPredicateProbe("$.academicSessions[*].type", 
						 JsonPredicates.valueMatches(Pattern.compile("(foo|bar)")), 
						 "The type field should have either of the values 'foo' or 'bar'", WARNING))												
				//this one succeeds
				.add(ACADEMIC_SESSIONS_GET_200, new MyCustomTest())
				
				.build();
		
		Report result = validator.run(rsrc);
		//PrintHelper.print(result, true);
		String failTestID1 = "JsonPropertyPresentProbe|$.academicSessions[*]|foo";
		String failTestID2 = "JsonPropertyPredicateProbe|$.academicSessions[*].type|The.type.field.should.have.either.of.the.values.'foo'.or.'bar'";
		String failTestID3 = "JsonPropertyPredicateProbe|$.academicSessions[*].status|The.status.field.does.not.have.expected.value.'foo'";
		String succTestID1 = "JsonPropertyPresentProbe|$.academicSessions[*]|status";
		String succTestID2 = "JsonSchemaProbe|getAllAcademicSessions-200-responsepayload-schema.json";
		String succTestID3 = MyCustomTest.ID;

		assertFalse(result.getOutcome() == Outcome.VALID);
		assertEquals(6,  result.size());
		assertEquals(3,  result.size(true));
		assertTrue(result.contains(Outcome.WARNING));
		assertTrue(result.contains(Outcome.ERROR));
		assertTrue(result.contains(Outcome.VALID));
		
		assertTrue(result.contains(failTestID1));
		assertTrue(result.contains(failTestID2));
		assertTrue(result.contains(failTestID3));
		assertTrue(result.contains(succTestID1));
		assertTrue(result.contains(succTestID2));
		assertTrue(result.contains(succTestID3));
		assertEquals(6,  result.asMap().keySet().size());
				
	}
	
	static final class MyCustomTest extends org.oneedtech.inspect.core.probe.Probe<JsonNode, JsonContext> {
		static final String ID = "MyCustomTestID"; 
		
		public MyCustomTest() {
			super(ID);
		}
		
		@Override
		public ReportItems run(JsonNode root, JsonContext context) throws Exception {
			//do something		
			
			//return 
			return success(this, context);
		}		
	}
		
	@Disabled
	@Test
	void testAllPerformanceLoop() throws Exception {
		List<Sample> input = Sample.fieldsToList(Samples.OR11.class.getFields());
				
		//read each sample into a string
		Map<Sample, String> data = new LinkedHashMap<>();
		for(Sample sample : input) {
			data.put(sample, sample.asString());
		}
				
		Multimap<Sample, RunData> results = ArrayListMultimap.create(); 
		
		Stopwatch total = Stopwatch.createStarted();
		int runs = 0;
		for (int i = 0; i < 10; i++) {			
			for(Sample sample : data.keySet()) {
				//System.gc();
				++runs;
				String body = data.get(sample); 
				String endPoint = sample.getTransactionKey().orElseThrow().getEndpoint();
				int code = sample.getTransactionKey().orElseThrow().getStatusCodes()[0];
				
				Resource resource = new StringResource(body, "myID", GET, endPoint, code);
				
				Stopwatch watch = Stopwatch.createStarted();
				Report result = inspector.run(resource);				
				watch.stop();
				
				assertTrue(result.getOutcome() == Outcome.VALID == sample.isValid());
				assertTrue(result.getOutcome() == Outcome.VALID ? result.size(true) < 1 : result.size(true) > 0 );
				
				results.put(sample, new RunData(watch, result.size(true)));				
			}	
		}
		total.stop();
		long totalMs = total.elapsed(TimeUnit.MILLISECONDS);
		
		System.out.println("Total " + runs + " runs in " + totalMs + " ms (average: " +  (totalMs/runs) +" ms).");
		
		for(Sample sample : results.keySet()) {
			Collection<RunData> rd = results.get(sample);
			int msgs = rd.iterator().next().messageCount;
			long avgMs = average(rd);
			System.out.println("Average " + avgMs + "ms on " + sample.getLocation() + " (isValid: " + sample.isValid() + ", msgs: " + msgs + ")");			
		}
		
		//System.out.println(allDefaultsOneRoster11Validator.delegates.stats().toString());
		
	}
	
	private long average(Collection<RunData> rds) {
		long total = 0;
		for(RunData rd : rds ) {
			 total += rd.watch.elapsed(TimeUnit.MILLISECONDS);
		}
		return total/rds.size();
	}

	public static final class RunData {
		public final Stopwatch watch;
		public final int messageCount;
		public RunData(Stopwatch watch, int messageCount) {
			this.watch = watch;
			this.messageCount = messageCount;
		}		
	}
}
