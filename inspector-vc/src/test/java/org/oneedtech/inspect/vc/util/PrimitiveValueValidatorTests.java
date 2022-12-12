package org.oneedtech.inspect.vc.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.List;
import java.util.function.Function;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.vc.Assertion.ValueType;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test case for PrimitiveValueValidator.
 * Maps to "PropertyValidationTests" in python implementation
 */
public class PrimitiveValueValidatorTests {
	private static ObjectMapper mapper;

	@BeforeAll
	static void setup() {
		mapper = ObjectMapperCache.get(DEFAULT);
	}

	@Test
	void testDataUri() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("data:image/gif;base64,R0lGODlhyAAiALM...DfD0QAADs=",
										  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==",
										  "data:text/plain;charset=UTF-8;page=21,the%20data:1234,5678",
										  "data:text/vnd-example+xyz;foo=bar;base64,R0lGODdh",
										  "data:,actually%20a%20valid%20data%20URI",
										  "data:,");
		List<String> badValues = List.of("data:image/gif",
										 "http://someexample.org",
										 "data:bad:path");
		assertFunction(ValueType.DATA_URI, goodValues, badValues);
	}

	@Test
	void testDataUriOrUrl() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("data:image/gif;base64,R0lGODlhyAAiALM...DfD0QAADs=",
										  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==",
										  "data:text/plain;charset=UTF-8;page=21,the%20data:1234,5678",
										  "data:text/vnd-example+xyz;foo=bar;base64,R0lGODdh",
										  "http://www.example.com:8080/", "http://www.example.com:8080/foo/bar",
										  "http://www.example.com/foo%20bar", "http://www.example.com/foo/bar?a=b&c=d",
										  "http://www.example.com/foO/BaR", "HTTPS://www.EXAMPLE.cOm/",
										  "http://142.42.1.1:8080/", "http://142.42.1.1/",
										  "http://foo.com/blah_(wikipedia)#cite-1", "http://a.b-c.de",
										  "http://userid:password@example.com/", "http://-.~:%40:80%2f:password@example.com",
										  "http://code.google.com/events/#&product=browser");
		List<String> badValues = List.of("///", "///f", "//",
										 "rdar://12345", "h://test", ":// should fail", "", "a",
										 "urn:uuid:129487129874982374", "urn:uuid:9d278beb-36cf-4bc8-888d-674ff9843d72");
		assertFunction(ValueType.DATA_URI_OR_URL, goodValues, badValues);
	}

	@Test
	void testUrl() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("http://www.example.com:8080/", "http://www.example.com:8080/foo/bar",
										  "http://www.example.com/foo%20bar", "http://www.example.com/foo/bar?a=b&c=d",
										  "http://www.example.com/foO/BaR", "HTTPS://www.EXAMPLE.cOm/",
										  "http://142.42.1.1:8080/", "http://142.42.1.1/", "http://localhost:3000/123",
										  "http://foo.com/blah_(wikipedia)#cite-1", "http://a.b-c.de",
										  "http://userid:password@example.com/", "http://-.~:%40:80%2f:password@example.com",
										  "http://code.google.com/events/#&product=browser");
		List<String> badValues = List.of("data:image/gif;base64,R0lGODlhyAAiALM...DfD0QAADs=", "///", "///f", "//",
										 "rdar://12345", "h://test", ":// should fail", "", "a",
										 "urn:uuid:129487129874982374", "urn:uuid:9d278beb-36cf-4bc8-888d-674ff9843d72");
		assertFunction(ValueType.URL, goodValues, badValues);
	}

	@Test
	void testIri() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("http://www.example.com:8080/", "_:b0", "_:b12", "_:b107", "_:b100000001232",
										  "urn:uuid:9d278beb-36cf-4bc8-888d-674ff9843d72",
										  "urn:uuid:9D278beb-36cf-4bc8-888d-674ff9843d72");
		List<String> badValues = List.of("data:image/gif;base64,R0lGODlhyAAiALM...DfD0QAADs=", "urn:uuid", "urn:uuid:123",
										 "", "urn:uuid:", "urn:uuid:zz278beb-36cf-4bc8-888d-674ff9843d72");
		assertFunction(ValueType.IRI, goodValues, badValues);
	}

	@Test
	void testUrlAuthority() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("google.com", "nerds.example.com");
		List<String> badValues = List.of("666", "http://google.com/", "https://www.google.com/search?q=murder+she+wrote&oq=murder+she+wrote",
										 "ftp://123.123.123.123", "bears", "lots of hungry bears", "bears.com/thewoods",
										 "192.168.0.1", "1::6:7:8");
		assertFunction(ValueType.URL_AUTHORITY, goodValues, badValues);
	}

	@Test
	void testCompactedIRI() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("id", "email", "telephone", "url");
		List<String> badValues = List.of("sloths");
		assertFunction(ValueType.COMPACT_IRI, goodValues, badValues);
	}

	@Test
	void testBasicText() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("string value");
		List<Integer> badValues = List.of(3, 4);
		assertFunction(ValueType.TEXT, goodValues, badValues);
	}

	@Test
	void testTelephone() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("+64010", "+15417522845", "+18006664358", "+18006662344;ext=666");
		List<String> badValues = List.of("1-800-666-DEVIL", "1 (555) 555-5555", "+99 55 22 1234", "+18006664343 x666");
		assertFunction(ValueType.TELEPHONE, goodValues, badValues);
	}

	@Test
	void testEmail() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("abc@localhost", "cool+uncool@example.org");
		List<String> badValues = List.of(" spacey@gmail.com", "steveman [at] gee mail dot com");
		assertFunction(ValueType.EMAIL, goodValues, badValues);
	}

	@Test
	void testBoolean() throws JsonMappingException, JsonProcessingException {
		List<Boolean> goodValues = List.of(true, false);
		List<String> badValues = List.of(" spacey@gmail.com", "steveman [at] gee mail dot com");
		assertFunction(ValueType.BOOLEAN, goodValues, badValues);
	}

	@Test
	void testDateTime() throws JsonMappingException, JsonProcessingException {
		List<String> goodValues = List.of("1977-06-10T12:00:00+0800",
										  "1977-06-10T12:00:00-0800",
										  "1977-06-10T12:00:00+08",
										  "1977-06-10T12:00:00+08:00");
		List<String> badValues = List.of("notadatetime", "1977-06-10T12:00:00");
		assertFunction(ValueType.DATETIME, goodValues, badValues);
	}

	private void assertFunction(ValueType valueType, List<? extends Object> goodValues, List<? extends Object> badValues) throws JsonMappingException, JsonProcessingException {
		Function<JsonNode, Boolean> validationFunction = valueType.getValidationFunction();
		for (Object goodValue : goodValues) {
			assertTrue(validationFunction.apply(parseNode(goodValue)),
					   "`" + goodValue + "` should pass " + valueType + " validation but failed.");
		}
		for (Object badValue : badValues) {
			assertFalse(validationFunction.apply(parseNode(badValue)),
					    "`" + badValue + "` should fail " + valueType + " validation but passed.");
		}
	}

	private JsonNode parseNode(Object value) throws JsonMappingException, JsonProcessingException {
		if (value instanceof String) {
			return mapper.readTree("\"" + value + "\"");
		}
		return mapper.readTree(value.toString());
	}
}
