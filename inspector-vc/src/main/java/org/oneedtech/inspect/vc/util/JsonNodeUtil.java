package org.oneedtech.inspect.vc.util;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Node access utilities.
 * @author mgylling
 */
public class JsonNodeUtil {

	/**
	 * Get all embedded endorsement objects as a flat list.
	 * @return a List that is never null but may be empty.
	 */
	public static List<JsonNode> getEndorsements(JsonNode root, JsonPathEvaluator jsonPath) {
		List<JsonNode> list = new ArrayList<>();		
		ArrayNode endorsements = jsonPath.eval("$..endorsement", root);	
		for(JsonNode endorsement : endorsements) {
			ArrayNode values = (ArrayNode) endorsement;
			for(JsonNode value : values) {
				list.add(value);
			}
		}
		return list;
	}
	
	public static List<String> asStringList(JsonNode node) {
		if(!(node instanceof ArrayNode)) {
			return List.of(node.asText());
		} else {
			ArrayNode arrayNode = (ArrayNode)node;			
			return StreamSupport
					.stream(arrayNode.spliterator(), false)
					.map(n->n.asText().strip())
					.collect(Collectors.toList());	
		}
	}
	
	public static List<JsonNode> asNodeList(JsonNode node) {
		if(node == null) return null;
		if(!(node instanceof ArrayNode)) {
			return List.of(node);
		} else {
			ArrayNode arrayNode = (ArrayNode)node;			
			return StreamSupport
					.stream(arrayNode.spliterator(), false)
					.collect(Collectors.toList());	
		}
	}
}
