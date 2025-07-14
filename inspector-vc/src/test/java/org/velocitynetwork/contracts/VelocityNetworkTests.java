package org.velocitynetwork.contracts;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonWriter;
import jnr.posix.Crypt;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URISyntaxException;

public class VelocityNetworkTests {
    private static String issuerDID = "did:example:eSySaEKsmsDm5E2XyQARv";
    private static String credentialDID = "did:velocity:v2:123:456:789";
    private static String encryptedKeyString = "174dfc5352638f69897e417c1dacd7e36aa5979c6bd50a83cdb31926675ce8e84cb66a7313ac15de368318df6a01a70af63c2c5b312acb4c2fffbf94fefea43b210454d2be0694b790c153d6085839796f5baf20a0bc17607af7fda28572a66645ae3ed16716523465e4b5eece92d786e2c685596543ad4ba931f46b37758a98bfbb316872e164f77ccbcae57ffb0700fd0ce579aed312bb295dc1dfd0e5ff7b79c874b6418ebde72188484754fd2e34ac3973d4cdc7143ac1609de978969fefe3b7e7e87075d05e7a39cbb9a1f5e0af59a0ca9591e927efa12be3f8f47d9be9404d7a66f76a356ec1f6a7fa";
    private static byte[] encryptedKey = CryptoUtils.hexToBytes(encryptedKeyString);

    private static byte[] version = CryptoUtils.hexToBytes("0x3bfc");
    private static byte[] credentialType = CryptoUtils.hexToBytes("0x2936");
    private static byte[] algType = CryptoUtils.hexToBytes("0xd19a");
    private static byte[] issuerVc = CryptoUtils.hexToBytes("0x65794a30655841694f694a4b563151694c434a68624763694f694a46557a49314e6b73694c434a72615751694f694a6b615751365a586868625842735a54706c55336c545955564c6332317a5247303152544a5965564642556e596a646d567362324e7064486b74613256354c54456966512e65794a325979493665794a705a434936496d5630614756795a5856744f6e56755a47566d6157356c5a43396e5a5854516f584a6c5a47567564476c686245316c6447466b5958526854476c7a64456c7a6333566c636c5a445032466b5a484a6c63334d394d48686c4d7a6b78516a597a52544979597a55304d6a564351554d314f5451334d7a6b314e4467334e324d304e5441304f575269516a63794a6d78706333524a5a4430794e5441304d5449314d6a67794e7a4d7a4f446b694c434a306558426c496a7062496b4e795a57526c626e52705957784e5a5852685a47463059557870633352495a57466b5a5849695853776961584e7a64575679496a6f695a476c6b4f6d563459573177624755365a564e355532464653334e74633052744e55557957486c5251564a324969776959334a6c5a47567564476c6862464e31596d706c593351694f6e736962476c7a64456c6b496a6f794e5441304d5449314d6a67794e7a4d7a4f446b73496d466a59323931626e524a5a434936496a42345a544d354d5549324d3055794d6d4d314e444931516b46444e546b304e7a4d354e5451344e7a646a4e4455774e446c6b596b49334d694a3966537769626d4a6d496a6f784e7a49774e6a59334e7a59794c434a7164476b694f694a6c6447686c636d563162547031626d526c5a6d6c755a5751765a325630304b46795a57526c626e52705957784e5a5852685a474630595578706333524a63334e315a584a57517a39685a4752795a584e7a505442345a544d354d5549324d3055794d6d4d314e444931516b46444e546b304e7a4d354e5451344e7a646a4e4455774e446c6b596b49334d695a7361584e30535751394d6a55774e4445794e5449344d6a637a4d7a67354969776961584e7a496a6f695a476c6b4f6d563459573177624755365a564e355532464653334e74633052744e55557957486c5251564a324969776961574630496a6f784e7a49774e6a59334e7a597966512e47345774666d77344531626557635f4142354b4f6b663248574141626e5a3379654b7263526a3439433650346b4e7451512d384d656c6c6e444c747236437046774867364f324354446f7671775a3134337944614f51");

    private static JsonObject publicRSAJwk = Json.createObjectBuilder()
            .add("kty", "RSA")
            .add("n", "sXchOWzJQX8Mmy5xkFJ8vWwOSXvNLXxkIg0FkgSsn6AyzPMZcRJPzHZjW8UdP5smN4k_0HxZY9VZJtIBaU2zUb9DdKhSbJq6q5UgZqzqNmldOBy5MOxuTxgOdxIQ9V9OLChw46wxkKjqsoKvzMGeBAIsQaXgmIkqgLf5nKr3dHgE")
            .add("e", "AQAB")
            .build();

    String secret = "6fc13e4032a30cd61060d669cf931f4fa8de043a76f32df500bffb15aded78f8";

    private static boolean verbose = true;

    @BeforeAll
    static void setup() {}

    @Test
    void testHexConversion() {
        Assertions.assertEquals("00", CryptoUtils.bytesToHex(CryptoUtils.hexToBytes("00")));
        Assertions.assertEquals("6b86", CryptoUtils.bytesToHex(CryptoUtils.hexToBytes("6b86")));
        Assertions.assertEquals("ffff", CryptoUtils.bytesToHex(CryptoUtils.hexToBytes("ffff")));
        Assertions.assertEquals("3bfc", CryptoUtils.bytesToHex(CryptoUtils.hexToBytes("0x3bfc")));
    }

    @Test
    void test2BytesHex() {
        Assertions.assertEquals("3bfc", CryptoUtils.get2BytesHash("v1"));
        Assertions.assertEquals("2936", CryptoUtils.get2BytesHash("OpenBadgeCredential"));
    }

    @Test
    void testPublicKeyloading() {
        VelocityNetworkMetadataRegistry.CredentialMetadata cm = new VelocityNetworkMetadataRegistry.CredentialMetadata(version, credentialType, algType, encryptedKey, issuerVc);

        JsonObject publicKey = VelocityNetworkDidResolver.PublicKeyResolver.resolvePublicKey(credentialDID, cm, secret);
        Assertions.assertEquals(Json.createObjectBuilder()
                .add("id", credentialDID + "#key-1")
                .add("publicKeyJwk", publicRSAJwk)
                .add("controller", issuerDID)
                .build(),
                publicKey);
    }
}
