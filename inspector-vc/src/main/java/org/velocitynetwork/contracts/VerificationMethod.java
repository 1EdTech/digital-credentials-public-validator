package org.velocitynetwork.contracts;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.web3j.crypto.Secp256k1JWK;

public class VerificationMethod {
    public static JsonObject buildVerificationMethod(String id, String controller, Secp256k1JWK publicKeyJwk) {
        JsonObjectBuilder publicKeyJwkJson = Json.createObjectBuilder()
                .add("kty", publicKeyJwk.getKty())
                .add("crv", publicKeyJwk.getCrv())
                .add("x", publicKeyJwk.getX())
                .add("y", publicKeyJwk.getY());
        if (publicKeyJwk.getD() != null) {
            publicKeyJwkJson.add("d", publicKeyJwk.getD());
        }
        return Json.createObjectBuilder().add("id", id).add("publicKeyJwk", publicKeyJwkJson).add("controller", controller).build();
    }

    public static JsonObject buildVerificationMethod(String id) {
        return Json.createObjectBuilder().add("id", id).build();
    }
}