package org.velocitynetwork.contracts;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.util.Arrays;

public class CredentialMetadataKDF {
    public static String derive(String contentHashHex) {
        byte[] contentHash = CryptoUtils.hexToBytes(contentHashHex);
        byte[] salt = Arrays.copyOfRange(contentHash, contentHash.length - 16, contentHash.length);

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
                .withSalt(salt)
                .withMemoryAsKB(4096)
                .withParallelism(1)
                .withIterations(3);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] output = new byte[32];
        generator.generateBytes(contentHash, output);

        return CryptoUtils.bytesToHex(output);
    }
}
