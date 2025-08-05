package org.velocitynetwork.contracts;

import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

import java.util.HexFormat;

public class CryptoUtils {
    public static String hashAndEncodeHex(String value) {
        byte[] inputBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] hash = Hash.sha256(inputBytes);
        return Numeric.toHexStringNoPrefix(hash); // hex string without "0x" prefix
    }

    public static String get2BytesHash  (String value) {
        String hash = hashAndEncodeHex(value);
        return hash.substring(0, 4);
    };

    public static byte[] hexToBytes(String hex) {
        String strippedHex = hex.startsWith("0x") ? hex.substring(2) : hex;
        return HexFormat.of().parseHex(strippedHex);
    }

    public static String bytesToHex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
