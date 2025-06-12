package org.velocitynetwork.contracts;

import org.web3j.abi.TypeEncoder;
import org.web3j.abi.datatypes.Address;
import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

public class SignUtils {

    /**
     * Signs an Ethereum address using a private key.
     * @param address Ethereum address (e.g., "0x123...")
     * @param privateKey Private key in hex (no "0x")
     * @return Hex-encoded 65-byte signature (r + s + v)
     */
    public static String signAddress(String address, String privateKey) {
        // 1. ABI encode the address (padded 32 bytes)
        String encodedAddressHex = TypeEncoder.encode(new Address(address));
        byte[] encoded = Numeric.hexStringToByteArray(encodedAddressHex);

        // 2. Hash using Keccak-256
        byte[] hash = Hash.sha3(encoded);

        // 3. Sign the hash
        ECKeyPair keyPair = ECKeyPair.create(Numeric.hexStringToByteArray(privateKey));
        Sign.SignatureData signature = Sign.signMessage(hash, keyPair, false); // false = raw hash, no Ethereum prefix

        // 4. Serialize signature (r + s + v)
        return serializeSignature(signature);
    }

    private static String serializeSignature(Sign.SignatureData sig) {
        byte[] r = sig.getR();
        byte[] s = sig.getS();
        byte[] v = sig.getV();

        byte[] signature = new byte[65];
        System.arraycopy(r, 0, signature, 0, 32);
        System.arraycopy(s, 0, signature, 32, 32);
        signature[64] = v[0];

        return Numeric.toHexString(signature);
    }
}