package org.oneedtech.inspect.vc.jsonld;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import foundation.identity.jsonld.JsonLDObject;

public class JsonLDObjectUtils {
	@SuppressWarnings("unchecked")
    public static <C extends JsonLDObject> List<C> getListFromJsonLDObject(Class<C> cl, JsonLDObject jsonLdObject) {
		String term = JsonLDObject.getDefaultJsonLDPredicate(cl);
		List<Map<String, Object>> jsonObjects = jsonLdGetJsonObjectList(jsonLdObject.getJsonObject(), term);
		if (jsonObjects == null) return null;
		try {
			Method method = cl.getMethod("fromMap", Map.class);
			return jsonObjects.stream().map(jsonObject ->  {
				try {
					return (C) method.invoke(null, jsonObject);
				} catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					throw new Error(e);
				}
			}).collect(Collectors.toList());
		} catch (NoSuchMethodException | SecurityException e) {
			throw new Error(e);
		}
	}

	@SuppressWarnings("unchecked")
    public static List<Map<String, Object>> jsonLdGetJsonObjectList(Map<String, Object> jsonObject, String term) {
		Object entry = jsonObject.get(term);
		if (entry == null) return null;

		if (entry instanceof Map<?, ?>) {
			return Collections.singletonList((Map<String, Object>) entry);
		} else if (entry instanceof List<?> && ((List<Object>) entry).stream().allMatch(e -> e instanceof Map<?, ?>)) {
			return (List<Map<String, Object>>) (List<Map<String,Object>>) entry;
		} else {
			throw new IllegalArgumentException("Cannot get json object '" + term + "' from " + jsonObject);
		}
	}
}
