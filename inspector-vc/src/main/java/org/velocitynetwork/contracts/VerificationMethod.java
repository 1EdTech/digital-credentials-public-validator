package org.velocitynetwork.contracts;

import com.authlete.cose.COSEKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;

import java.util.Map;

public class VerificationMethod {
    public static JsonObject buildVerificationMethod(String id, String controller, COSEKey coseKey) {
        Map<String, Object> jwk = coseKey.toJwk();
        return Json.createObjectBuilder().add("id", id).add("publicKeyJwk", Json.createObjectBuilder(jwk)).add("controller", controller).build();
    }

    public static JsonObject buildVerificationMethod(String id) {
        return Json.createObjectBuilder().add("id", id).build();
    }
}