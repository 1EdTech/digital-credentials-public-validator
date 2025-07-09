package org.velocitynetwork.contracts;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEKey;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.oneedtech.inspect.util.code.Tuple;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Secp256k1JWK;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.StaticGasProvider;

import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

import static java.util.UUID.randomUUID;

public class VelocityNetworkDidResolver {
    static class IssuerVc {
        public static JsonObject deserializeIssuerVc(VelocityNetworkMetadataRegistry.CredentialMetadata metadataEntry) {
            return Json.createReader(new StringReader(new String(metadataEntry.issuerVc, StandardCharsets.UTF_8))).readObject();
        }
    }

    static class PublicKeyResolver {
        private static final String VERSION = CryptoUtils.get2BytesHash("v1");
        private static final String ALG_TYPE = CryptoUtils.get2BytesHash("secp256k1");

        public static BCECPublicKey fromRawPublicKey(byte[] pubKeyBytes) throws Exception {
            // 1. Get curve parameters
            ECNamedCurveParameterSpec curveSpec = ECNamedCurveTable.getParameterSpec("secp256k1");

            // 2. Decode the public key bytes to ECPoint
            ECPoint point = curveSpec.getCurve().decodePoint(pubKeyBytes);

            // 3. Build public key spec
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curveSpec);

            // 4. Create BCECPublicKey
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            return (BCECPublicKey) pubKey;
        }

        public static JsonObject resolvePublicKey(String id, VelocityNetworkMetadataRegistry.CredentialMetadata entry, String secret) {
            if (!entry.version.equals((VERSION)) || !entry.algType.equals(ALG_TYPE)) {
                throw new IllegalArgumentException("Unsupported encryption algorithm \"" + ALG_TYPE + "\" or version \"" + VERSION + "\"");
            }

            try {
                byte[] publicKeyBytes = AesGcmEncryptor.decrypt(entry.encryptedPublicKey, secret);
                CBORItem item = new CBORDecoder(publicKeyBytes).next();
                COSEKey coseKey = COSEKey.build(item);
                if ((Integer) coseKey.getKty() == 3) {
                    coseKey = new COSERSAKey(coseKey.getPairs());
                }
                JsonObject issuerVcJwt = IssuerVc.deserializeIssuerVc(entry);
                return VerificationMethod.buildVerificationMethod(id + "#key-1", issuerVcJwt.getJsonObject("payload").getString("iss"), coseKey);
            } catch (Exception e) {
                return VerificationMethod.buildVerificationMethod(id);
            }
        }
    }

    private VelocityNetworkMetadataRegistry metadataRegistryContract;
    private String burnerDid;
    private Credentials credentials;

    public VelocityNetworkDidResolver(String rpcUrl, String privateKey, String contractAddress, String burnerDid) {
        Web3j web3 = Web3j.build(new HttpService(rpcUrl));
        this.burnerDid = burnerDid;
        this.credentials = Credentials.create(privateKey);
        this.metadataRegistryContract = org.velocitynetwork.contracts.VelocityNetworkMetadataRegistry.load(contractAddress, web3, credentials, new StaticGasProvider(BigInteger.ZERO, BigInteger.ZERO));
    }

    public JsonObject resolveDid(String did) throws Exception {
        List<Tuple<VelocityNetworkMetadataRegistry.CredentialIdentifier, String>> parsedDid = parseVelocityV2Did(did);
        TransactionReceipt transactionReceipt = this.metadataRegistryContract.getPaidEntries(parsedDid.stream().map(tuple -> tuple.t1).toList(), randomUUID().toString(), burnerDid, burnerDid).send();
        List<VelocityNetworkMetadataRegistry.CredentialMetadata> metadataEntries =
                VelocityNetworkMetadataRegistry.getGotCredentialMetadataEvents(transactionReceipt).getLast().credentialMetadataList;

        List<JsonObject> verificationMethods =
                IntStream
                    .range(0, metadataEntries.size())
                    .mapToObj(i ->
                            PublicKeyResolver.resolvePublicKey(
                                    did,
                                    metadataEntries.get(i),
                                    CredentialMetadataKDF.derive(parsedDid.get(i).t2)
                            )
                    )
                    .toList();
        return Json.createObjectBuilder()
                .add("id", did)
                .add("verificationMethod", Json.createArrayBuilder(verificationMethods))
                .add("assertionMethod", Json.createArrayBuilder(verificationMethods.stream().map(verificationMethod -> verificationMethod.get("id")).toList()))
                .build();
    }

    public static List<Tuple<VelocityNetworkMetadataRegistry.CredentialIdentifier, String>> parseVelocityV2Did(String did) {
        if (!did.startsWith("did:velocity:v2:")) {
            throw new IllegalArgumentException("Wrong did: " + did);
        }

        final String multiToken = ":multi:";

        if (!did.contains(multiToken)) {
            String[] parts = did.split(":");
            if (parts.length < 7) {
                throw new IllegalArgumentException("Invalid single-entry DID: " + did);
            }
            return List.of(new Tuple<>(new VelocityNetworkMetadataRegistry.CredentialIdentifier(parts[3], new BigInteger(parts[4]), new BigInteger(parts[5])), parts[6]));
        }

        String[] split = did.split(multiToken, 2);
        String entriesPart = split[1];

        return Arrays.stream(entriesPart.split(";"))
                .map(entryString -> {
                    String[] subParts = entryString.split(":");
                    if (subParts.length != 4) {
                        throw new IllegalArgumentException("Invalid multi-entry DID segment: " + entryString);
                    }
                    return new Tuple<>(new VelocityNetworkMetadataRegistry.CredentialIdentifier(subParts[0], new BigInteger(subParts[1]), new BigInteger(subParts[2])), subParts[3]);
                })
                .toList();
    }
}
