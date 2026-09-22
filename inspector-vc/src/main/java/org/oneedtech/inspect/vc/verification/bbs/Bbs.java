package org.oneedtech.inspect.vc.verification.bbs;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.miracl.core.HMAC;
import org.miracl.core.BLS12381.BIG;
import org.miracl.core.BLS12381.CONFIG_BIG;
import org.miracl.core.BLS12381.DBIG;
import org.miracl.core.BLS12381.ECP;
import org.miracl.core.BLS12381.ECP2;
import org.miracl.core.BLS12381.FP;
import org.miracl.core.BLS12381.FP2;
import org.miracl.core.BLS12381.ROM;

/**
 * Constants and low-level primitives for the ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_,
 * as specified by draft-irtf-cfrg-bbs-signatures (https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-06.html),
 * built on top of the vendored MIRACL Core BLS12-381 primitives (org.miracl.core.BLS12381).
 */
public final class Bbs {

  private Bbs() {}

  public static final String CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
  public static final byte[] API_ID = concat(bytes(CIPHERSUITE_ID), bytes("H2G_HM2S_"));

  public static final int OCTET_SCALAR_LENGTH = 32;
  public static final int OCTET_POINT_LENGTH_G1 = 48;
  public static final int OCTET_POINT_LENGTH_G2 = 96;
  public static final int EXPAND_LEN = 48;

  /* L = ceil((ceil(log2(p)) + k) / 8) with k = 128 (security level) for BLS12-381 (p is 381 bits) */
  private static final int HASH_TO_CURVE_L = 64;

  private static final String P1_HEX =
      "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

  /** Fixed point of G1 defined by the ciphersuite. */
  public static final ECP P1 = decodeG1Unchecked(hexToBytes(P1_HEX));

  public static BIG order() {
    return new BIG(ROM.CURVE_Order);
  }

  public static BIG fieldModulus() {
    return new BIG(ROM.Modulus);
  }

  public static ECP2 g2Generator() {
    return ECP2.generator();
  }

  public static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  public static byte[] concat(byte[]... parts) {
    int len = 0;
    for (byte[] p : parts) len += p.length;
    byte[] out = new byte[len];
    int pos = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, pos, p.length);
      pos += p.length;
    }
    return out;
  }

  /** I2OSP for an unsigned integer value, big-endian, fixed length. */
  public static byte[] i2osp(long value, int length) {
    byte[] out = new byte[length];
    for (int i = length - 1; i >= 0 && value != 0; i--) {
      out[i] = (byte) (value & 0xff);
      value >>>= 8;
    }
    return out;
  }

  /** I2OSP for a scalar (BIG), always OCTET_SCALAR_LENGTH bytes. */
  public static byte[] i2ospScalar(BIG scalar) {
    byte[] full = new byte[org.miracl.core.BLS12381.CONFIG_BIG.MODBYTES];
    new BIG(scalar).toBytes(full);
    byte[] out = new byte[OCTET_SCALAR_LENGTH];
    System.arraycopy(
        full, full.length - OCTET_SCALAR_LENGTH, out, 0, OCTET_SCALAR_LENGTH);
    return out;
  }

  /** OS2IP for a 32-byte scalar octet string, returned unreduced (caller must range-check). */
  public static BIG os2ipScalar(byte[] bytes32) throws GeneralSecurityException {
    if (bytes32.length != OCTET_SCALAR_LENGTH) {
      throw new GeneralSecurityException("Invalid scalar length: " + bytes32.length);
    }
    int modBytes = org.miracl.core.BLS12381.CONFIG_BIG.MODBYTES;
    byte[] padded = new byte[modBytes];
    System.arraycopy(bytes32, 0, padded, modBytes - OCTET_SCALAR_LENGTH, OCTET_SCALAR_LENGTH);
    return BIG.fromBytes(padded);
  }

  /** Checks 0 < scalar < r. */
  public static boolean isValidNonZeroScalar(BIG scalar) {
    return BIG.comp(scalar, new BIG(0)) > 0 && BIG.comp(scalar, order()) < 0;
  }

  /*
   * MIRACL Core's own ECP/ECP2 toBytes/fromBytes only implement the "alt compressed" point format
   * (compression flag folded into the top bits of the x-coordinate, as used by zcash/IETF
   * pairing-friendly-curves Appendix C, and required by the BBS ciphersuite's point_to_octets_E*
   * and octets_to_point_E* functions) when ALLOW_ALT_COMPRESS is true -- which it is not
   * for this generated BLS12-381 curve (it defaults to a separate-flag-byte SEC1-style encoding
   * instead). The codec below reimplements the alt/zcash format directly against the FP/FP2/BIG
   * primitives, independent of that flag, and (unlike MIRACL's own alt-branch) explicitly honors
   * the infinity bit on decode, since MIRACL's raw x-only reconstruction has no way to recognize
   * the identity point's special encoding otherwise.
   */
  private static final int COMPRESSED_FLAG = 0x80;
  private static final int INFINITY_FLAG = 0x40;
  private static final int SIGN_FLAG = 0x20;

  public static byte[] pointToOctetsG1(ECP point) {
    byte[] out = new byte[OCTET_POINT_LENGTH_G1];
    ECP w = new ECP(point);
    w.affine();
    if (w.is_infinity()) {
      out[0] = (byte) (COMPRESSED_FLAG | INFINITY_FLAG);
      return out;
    }
    w.getx().toBytes(out);
    out[0] &= 0x1f;
    out[0] |= COMPRESSED_FLAG;
    if (w.gety().islarger() == 1) out[0] |= SIGN_FLAG;
    return out;
  }

  /** Deserializes a compressed G1 point, or returns null if invalid, infinity, or not in the subgroup. */
  public static ECP octetsToPointG1(byte[] bytes) throws GeneralSecurityException {
    if (bytes.length != OCTET_POINT_LENGTH_G1) return null;
    if ((bytes[0] & COMPRESSED_FLAG) == 0) {
      throw new GeneralSecurityException("Only compressed G1 points are supported");
    }
    ECP p = decodeG1Unchecked(bytes);
    if (p == null || p.is_infinity()) return null;
    if (!subgroupCheckG1(p)) return null;
    return p;
  }

  /** Decodes a compressed G1 point without a subgroup check; used for the ciphersuite's trusted P1 constant. */
  private static ECP decodeG1Unchecked(byte[] bytes) {
    if ((bytes[0] & INFINITY_FLAG) != 0) return new ECP();
    int sign = (bytes[0] & SIGN_FLAG) != 0 ? 1 : 0;
    byte[] xBytes = Arrays.copyOf(bytes, OCTET_POINT_LENGTH_G1);
    xBytes[0] &= 0x1f;
    BIG x = BIG.fromBytes(xBytes);
    if (BIG.comp(x, fieldModulus()) >= 0) return null;
    ECP p = new ECP(x, 0);
    if (p.is_infinity()) return null; // x has no valid square root on the curve
    // FP.islarger() returns -1/0/1 (not a boolean); normalize before comparing to the sign bit.
    int actualSign = p.gety().islarger() == 1 ? 1 : 0;
    if (actualSign != sign) p.neg();
    return p;
  }

  public static byte[] pointToOctetsG2(ECP2 point) {
    byte[] out = new byte[OCTET_POINT_LENGTH_G2];
    ECP2 w = new ECP2(point);
    w.affine();
    if (w.is_infinity()) {
      out[0] = (byte) (COMPRESSED_FLAG | INFINITY_FLAG);
      return out;
    }
    w.getx().toBytes(out);
    out[0] &= 0x1f;
    out[0] |= COMPRESSED_FLAG;
    if (w.gety().islarger() == 1) out[0] |= SIGN_FLAG;
    return out;
  }

  /** Decodes the signer's public key: a compressed G2 point, validated per octets_to_pubkey. */
  public static ECP2 octetsToPubkey(byte[] bytes) throws GeneralSecurityException {
    if (bytes.length != OCTET_POINT_LENGTH_G2) return null;
    if ((bytes[0] & COMPRESSED_FLAG) == 0) {
      throw new GeneralSecurityException("Only compressed G2 points are supported");
    }
    if ((bytes[0] & INFINITY_FLAG) != 0) return null;
    int sign = (bytes[0] & SIGN_FLAG) != 0 ? 1 : 0;
    byte[] xBytes = Arrays.copyOf(bytes, OCTET_POINT_LENGTH_G2);
    xBytes[0] &= 0x1f;
    FP2 x = FP2.fromBytes(xBytes);
    ECP2 w = new ECP2(x, 0);
    if (w.is_infinity()) return null; // x has no valid square root on the twist
    int actualSign = w.gety().islarger() == 1 ? 1 : 0;
    if (actualSign != sign) w.neg();
    if (!subgroupCheckG2(w)) return null;
    return w;
  }

  public static boolean subgroupCheckG1(ECP p) {
    ECP check = p.mul(order());
    return check.is_infinity();
  }

  public static boolean subgroupCheckG2(ECP2 p) {
    ECP2 check = p.mul(order());
    return check.is_infinity();
  }

  /** expand_message_xmd using SHA-256, per RFC 9380. */
  public static byte[] expandMessageXmd(byte[] msg, byte[] dst, int outLen) {
    return HMAC.XMD_Expand(HMAC.MC_SHA2, 32, outLen, dst, msg);
  }

  /** hash_to_scalar(msg, dst) = OS2IP(expand_message(msg, dst, expand_len)) mod r. */
  public static BIG hashToScalar(byte[] msg, byte[] dst) {
    byte[] uniformBytes = expandMessageXmd(msg, dst, EXPAND_LEN);
    DBIG d = DBIG.fromBytes(uniformBytes);
    return d.mod(order());
  }

  /**
   * hash_to_curve_g1(msg, dst): RFC 9380 hash_to_curve for BLS12381G1_XMD:SHA-256_SSWU_RO_
   * (random-oracle variant: two field elements, mapped and added, then cofactor-cleared).
   */
  public static ECP hashToCurveG1(byte[] msg, byte[] dst) {
    BIG p = fieldModulus();
    byte[] uniformBytes = expandMessageXmd(msg, dst, HASH_TO_CURVE_L * 2);
    byte[] b0 = Arrays.copyOfRange(uniformBytes, 0, HASH_TO_CURVE_L);
    byte[] b1 = Arrays.copyOfRange(uniformBytes, HASH_TO_CURVE_L, HASH_TO_CURVE_L * 2);
    FP u0 = new FP(DBIG.fromBytes(b0).mod(p));
    FP u1 = new FP(DBIG.fromBytes(b1).mod(p));
    ECP q0 = ECP.map2point(u0);
    ECP q1 = ECP.map2point(u1);
    q0.add(q1);
    q0.cfp();
    q0.affine();
    return q0;
  }

  public static byte[] hexToBytes(String hex) {
    int len = hex.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      out[i / 2] =
          (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
    }
    return out;
  }

  public static String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) sb.append(String.format("%02x", b));
    return sb.toString();
  }
}
