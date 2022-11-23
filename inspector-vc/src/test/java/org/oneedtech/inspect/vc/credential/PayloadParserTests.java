package org.oneedtech.inspect.vc.credential;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import org.junit.jupiter.api.Test;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.OB30Inspector;
import org.oneedtech.inspect.vc.Samples;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.payload.PayloadParser;
import org.oneedtech.inspect.vc.payload.PayloadParserFactory;
import org.oneedtech.inspect.vc.payload.PngParser;
import org.oneedtech.inspect.vc.payload.SvgParser;

import com.fasterxml.jackson.databind.ObjectMapper;

public class PayloadParserTests {

	@Test
	void testSvgStringExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.SVG.SIMPLE_JSON_SVG.asFileResource(ResourceType.SVG);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	@Test
	void testSvgJwtExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.SVG.SIMPLE_JWT_SVG.asFileResource(ResourceType.SVG);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	@Test
	void testPngStringExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.PNG.SIMPLE_JSON_PNG.asFileResource(ResourceType.PNG);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	@Test
	void testPngJwtExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.PNG.SIMPLE_JWT_PNG.asFileResource(ResourceType.PNG);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	@Test
	void testJwtExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.JWT.SIMPLE_JWT.asFileResource(ResourceType.JWT);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	@Test
	void testJsonExtract() {
		assertDoesNotThrow(()->{
			Resource res = Samples.OB30.JSON.SIMPLE_JSON.asFileResource(ResourceType.JSON);
			PayloadParser ext = PayloadParserFactory.of(res);
			assertNotNull(ext);
			Credential crd = ext.parse(res, mockOB30Context(res));
			//System.out.println(crd.getJson().toPrettyString());
			assertNotNull(crd);
			assertNotNull(crd.getJson());
			assertNotNull(crd.getJson().get("@context"));
		});
	}

	private RunContext mockOB30Context(Resource res) {
		ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
		JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);
		return new RunContext.Builder()
				.put(new OB30Inspector.Builder().build())
				.put(res)
				.put(Key.JACKSON_OBJECTMAPPER, mapper)
				.put(Key.JSONPATH_EVALUATOR, jsonPath)
				.put(Key.GENERATED_OBJECT_BUILDER, new VerifiableCredential.Builder())
				.put(Key.PNG_CREDENTIAL_KEY, PngParser.Keys.OB30)
				.put(Key.SVG_CREDENTIAL_QNAME, SvgParser.QNames.OB30)
				.build();
	}
}
