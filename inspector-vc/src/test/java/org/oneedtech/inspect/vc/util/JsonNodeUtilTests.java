package org.oneedtech.inspect.vc.util;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.vc.Samples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonNodeUtilTests {
	static final ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
	static final JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
	
	
	@Test
	void getEndorsementsTest() throws Exception {
		assertDoesNotThrow(()->{
			JsonNode root =  mapper.readTree(Samples.OB30.JSON.COMPLETE_JSON.asBytes());			
			List<JsonNode> list = JsonNodeUtil.getEndorsements(root, jsonPath);
			Assertions.assertEquals(5, list.size());
		});	
	}
}
