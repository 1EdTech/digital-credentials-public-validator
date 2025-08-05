package org.velocitynetwork.contracts;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.Security;

public class CredentialMetadataKDF {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static String derive(String passwordHex) {
        // Extract last 16 hex characters as salt
        byte[] salt = CryptoUtils.hexToBytes(passwordHex.substring(passwordHex.length() - 16));

        // Argon2 parameters
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_i)
                .withSalt(salt)
                .withMemoryAsKB(4096)
                .withParallelism(1)
                .withIterations(3);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] output = new byte[32]; // 256-bit key
        byte[] passwordBytes = passwordHex.getBytes(StandardCharsets.UTF_8);

        generator.generateBytes(passwordBytes, output, 0, output.length);

        return CryptoUtils.bytesToHex(output);
    }
}
