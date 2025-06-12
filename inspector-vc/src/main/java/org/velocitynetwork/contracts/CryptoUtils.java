package org.velocitynetwork.contracts;

import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;

class CryptoUtils {
    public static String hashAndEncodeHex(String value) {
        byte[] inputBytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] hash = Hash.sha256(inputBytes);
        return Numeric.toHexStringNoPrefix(hash); // hex string without "0x" prefix
    }

    public static String get2BytesHash  (String value) {
        String hash = hashAndEncodeHex(value);
        return "0x" + hash.substring(0, 4);
    };
}
