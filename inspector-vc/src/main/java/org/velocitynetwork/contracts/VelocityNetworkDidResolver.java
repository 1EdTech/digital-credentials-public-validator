package org.velocitynetwork.contracts;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cose.COSEKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import org.oneedtech.inspect.util.code.Tuple;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.StaticGasProvider;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;

import static java.util.UUID.randomUUID;

public class VelocityNetworkDidResolver {
    public static final String VELOCITY_NETWORK_METADATA_REGISTRY = "VELOCITY_NETWORK_METADATA_REGISTRY";

    static class IssuerVc {
        public static JWT deserializeIssuerVc(VelocityNetworkMetadataRegistry.CredentialMetadata metadataEntry) throws ParseException {
            String issuerVcString = new String(metadataEntry.issuerVc, StandardCharsets.UTF_8);
            return SignedJWT.parse(issuerVcString);
        }
    }

    public static class PublicKeyResolver {
        public static final String VERSION = CryptoUtils.get2BytesHash("1");
        public static final String ALG_TYPE = CryptoUtils.get2BytesHash("cosekey:aes-256-gcm");

        public static JsonObject resolvePublicKey(String id, VelocityNetworkMetadataRegistry.CredentialMetadata entry, String secret) {
            if (!CryptoUtils.bytesToHex(entry.version).equals((VERSION))) {
                throw new IllegalArgumentException("Unsupported encryption version \"" + VERSION + "\"");
            }
            if (!CryptoUtils.bytesToHex(entry.algType).equals(ALG_TYPE)) {
                throw new IllegalArgumentException("Unsupported encryption algorithm \"" + ALG_TYPE + "\"");
            }

            try {
                byte[] publicKeyBytes = AesGcmEncryptor.decrypt(entry.encryptedPublicKey, secret);
                CBORItem item = new CBORDecoder(publicKeyBytes).next();
                COSEKey coseKey = COSEKey.build(item);
                if ((Integer) coseKey.getKty() == 3) {
                    coseKey = new COSERSAKey(coseKey.getPairs());
                }
                JWT issuerVcJwt = IssuerVc.deserializeIssuerVc(entry);
                return VerificationMethod.buildVerificationMethod(id + "#key-1", issuerVcJwt.getJWTClaimsSet().getIssuer(), coseKey);
            } catch (Exception e) {
                System.err.println("Could not decrypt public key");
                System.err.println(e.getMessage());
                return VerificationMethod.buildVerificationMethod(id);
            }
        }
    }

    private VelocityNetworkMetadataRegistryFacade metadataRegistryContractFacade;
    private String burnerDid;

    public VelocityNetworkDidResolver(VelocityNetworkMetadataRegistryFacade velocityNetworkMetadataRegistryFacade, String burnerDid) {
        this.metadataRegistryContractFacade = velocityNetworkMetadataRegistryFacade;
        this.burnerDid = burnerDid;
    }

    public JsonObject resolveDid(String didUrl) throws Exception {
        try {
            String[] didParts = didUrl.split("#");
            String did = didParts[0];
            List<Tuple<VelocityNetworkMetadataRegistry.CredentialIdentifier, String>> parsedDid = parseVelocityV2Did(did);
            List<VelocityNetworkMetadataRegistry.CredentialMetadata> metadataEntries = this.metadataRegistryContractFacade.getPaidEntries(parsedDid.stream().map(tuple -> tuple.t1).toList(), randomUUID().toString(), burnerDid, burnerDid);

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

            // Should verify issuerVc for every metadataEntry, by using a SimpleDidResolver and running verify on the jwt.
            // If the entry does not verify then the public key should not be added to the verificationMethod. It should be part of
            // establishing the controller of the verificationMethod.
            return Json.createObjectBuilder()
                    .add("id", did)
                    .add("verificationMethod", Json.createArrayBuilder(verificationMethods))
                    .add("assertionMethod", Json.createArrayBuilder(verificationMethods.stream().map(verificationMethod -> verificationMethod.get("id")).toList()))
                    .build();
        } catch (Exception e) {
            System.err.println("Could not decrypt DID");
            System.err.println(e.getMessage());
            for (StackTraceElement ste : e.getStackTrace()) {
                System.out.println(ste);
            }
            throw new Exception(e.getMessage());
        }
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
