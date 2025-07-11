package org.oneedtech.inspect.vc.verification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAUtil {
	public static byte[] sha256(String string) {
		return com.danubetech.dataintegrity.util.SHAUtil.sha256(string);
	}

	public static byte[] sha384(String string) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("SHA-384");
		} catch (NoSuchAlgorithmException ex) {
			throw new RuntimeException(ex.getMessage(), ex);
		}
		return digest.digest(string.getBytes(StandardCharsets.UTF_8));
	}

}
