package org.velocitynetwork.contracts;

import com.authlete.cose.COSEKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.util.Map;

public class VerificationMethod {
    public static JsonObject buildVerificationMethod(String id, String controller, COSEKey coseKey) {
        Map<String, Object> jwk = coseKey.toJwk();
        JsonObjectBuilder jwkJson = Json.createObjectBuilder()
                .add("kty", (String) jwk.get("kty"))
                .add("n", (String) jwk.get("n"))
                .add("e", (String) jwk.get("e"));
        return Json.createObjectBuilder().add("id", id).add("publicKeyJwk", jwkJson).add("controller", controller).build();
    }

    public static JsonObject buildVerificationMethod(String id) {
        return Json.createObjectBuilder().add("id", id).build();
    }
}