package org.oneedtech.inspect.vc.util;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.vc.Samples;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

public class JsonNodeUtilTests {
	static final ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
	static final JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
	
	@Test
	void testFlattenNodeList() {
		Assertions.assertDoesNotThrow(()->{
			String json = Samples.OB30.JSON.COMPLETE_JSON.asString();
			JsonNode root = mapper.readTree(json);						
			List<JsonNode> list = JsonNodeUtil.asNodeList(root, "$..endorsement", jsonPath);
			Assertions.assertEquals(5, list.size());
			for(JsonNode node : list)  {
				ArrayNode types = (ArrayNode) node.get("type");
				boolean found = false;
				for(JsonNode val : types) {
					if(val.asText().equals("EndorsementCredential")) {
						found = true;
					}
				}
				assertTrue(found);
			}
					
		});
	}
	
}
