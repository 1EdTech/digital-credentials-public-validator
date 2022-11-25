package org.oneedtech.inspect.vc.util;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * Json node utilities.
 * @author mgylling
 */
public class JsonNodeUtil {

	public static List<JsonNode> asNodeList(JsonNode root, String jsonPath, JsonPathEvaluator evaluator) {
		List<JsonNode> list = new ArrayList<>();
		ArrayNode array = evaluator.eval(jsonPath, root);
		for(JsonNode node : array) {
			if(!(node instanceof ArrayNode)) {
				list.add(node);
			} else {
				ArrayNode values = (ArrayNode) node;
				for(JsonNode value : values) {
					list.add(value);
				}
			}
		}
		return list;
	}

	public static List<String> asStringList(JsonNode node) {
		if(!(node instanceof ArrayNode)) {
			if (node.isObject()) {
				return List.of();
			}
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
