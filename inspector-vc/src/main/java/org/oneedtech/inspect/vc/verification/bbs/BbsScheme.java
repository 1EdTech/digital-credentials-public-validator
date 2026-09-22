package org.oneedtech.inspect.vc.verification.bbs;

import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

import org.miracl.core.BLS12381.BIG;
import org.miracl.core.BLS12381.ECP;
import org.miracl.core.BLS12381.ECP2;
import org.miracl.core.BLS12381.FP12;
import org.miracl.core.BLS12381.PAIR;

/**
 * Implements the Verify and ProofVerify operations of the BBS signature scheme
 * (draft-irtf-cfrg-bbs-signatures-06, https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-06.html),
 * ciphersuite BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_.
 *
 * <p>Only verification is implemented (CoreVerify / CoreProofVerify and their subroutines) --
 * this project has no need to sign or produce proofs.
 */
public final class BbsScheme {

  private static final byte[] HASH_TO_SCALAR_DST = Bbs.concat(Bbs.API_ID, Bbs.bytes("H2S_"));
  private static final byte[] MAP_MSG_DST =
      Bbs.concat(Bbs.API_ID, Bbs.bytes("MAP_MSG_TO_SCALAR_AS_HASH_"));

  private BbsScheme() {}

  /** messages_to_scalars: maps each raw message octet string to a scalar. */
  public static List<BIG> messagesToScalars(List<byte[]> messages) {
    List<BIG> scalars = new ArrayList<>(messages.size());
    for (byte[] message : messages) {
      scalars.add(Bbs.hashToScalar(message, MAP_MSG_DST));
    }
    return scalars;
  }

  /**
   * CoreVerify: verifies a BBS signature over a header and a (possibly empty) list of messages.
   *
   * @param pk the signer's public key (96-byte compressed G2 point)
   * @param signature the signature octets (80 bytes: 48-byte G1 point || 32-byte scalar)
   * @param header the header octets
   * @param messages the signed messages, in the order they were signed
   */
  public static boolean verify(byte[] pk, byte[] signature, byte[] header, List<byte[]> messages)
      throws GeneralSecurityException {

    Signature sig = octetsToSignature(signature);
    ECP2 w = Bbs.octetsToPubkey(pk);
    if (w == null) return false;

    int l = messages.size();
    List<ECP> generators = BbsGenerators.createGenerators(l + 1);
    ECP q1 = generators.get(0);
    List<ECP> hPoints = generators.subList(1, generators.size());
    List<BIG> msgScalars = messagesToScalars(messages);

    BIG domain = calculateDomain(pk, q1, hPoints, header);

    ECP b = new ECP(Bbs.P1);
    b.add(q1.mul(domain));
    for (int i = 0; i < l; i++) {
      b.add(hPoints.get(i).mul(msgScalars.get(i)));
    }

    ECP2 bp2 = Bbs.g2Generator();
    ECP2 wPlusEBp2 = new ECP2(w);
    wPlusEBp2.add(bp2.mul(sig.e));
    ECP2 negBp2 = new ECP2(bp2);
    negBp2.neg();

    FP12 acc = PAIR.ate2(wPlusEBp2, sig.a, negBp2, b);
    acc = PAIR.fexp(acc);
    return acc.isunity();
  }

  /**
   * CoreProofVerify: verifies a BBS derived proof (selective disclosure) against a header,
   * presentation header, and the disclosed messages at their original indexes.
   *
   * @param pk the signer's public key (96-byte compressed G2 point)
   * @param proof the proof octets, as produced by ProofGen
   * @param header the header octets (must match the one used at signing time)
   * @param presentationHeader the presentation header octets bound into the proof
   * @param disclosedMessages the disclosed messages, in ascending index order
   * @param disclosedIndexes the original signed-message indexes of the disclosed messages, ascending
   */
  public static boolean proofVerify(
      byte[] pk,
      byte[] proof,
      byte[] header,
      byte[] presentationHeader,
      List<byte[]> disclosedMessages,
      List<Integer> disclosedIndexes)
      throws GeneralSecurityException {

    Proof proofResult = octetsToProof(proof);
    ECP2 w = Bbs.octetsToPubkey(pk);
    if (w == null) return false;

    int u = proofResult.commitments.size();
    int r = disclosedIndexes.size();
    int l = r + u;
    if (disclosedMessages.size() != r) return false;

    // disclosed_indexes MUST be supplied in ascending order, matching disclosedMessages
    // element-for-element (spec Section 3.7.3) -- verify that precondition rather than silently
    // re-sorting, which would desynchronize the two parallel lists if it were violated.
    for (int k = 0; k < r; k++) {
      int i = disclosedIndexes.get(k);
      if (i < 0 || i > l - 1) return false;
      if (k > 0 && disclosedIndexes.get(k - 1) >= i) return false;
    }
    TreeSet<Integer> disclosedSet = new TreeSet<>(disclosedIndexes);
    List<Integer> undisclosedIndexes = new ArrayList<>();
    for (int i = 0; i < l; i++) {
      if (!disclosedSet.contains(i)) undisclosedIndexes.add(i);
    }

    List<ECP> generators = BbsGenerators.createGenerators(l + 1);
    ECP q1 = generators.get(0);
    List<ECP> hPoints = generators.subList(1, generators.size());

    BIG domain = calculateDomain(pk, q1, hPoints, header);
    List<BIG> disclosedScalars = messagesToScalars(disclosedMessages);

    // T1 = Bbar * c + Abar * e^ + D * r1^
    ECP t1 = proofResult.bBar.mul(proofResult.c);
    t1.add(proofResult.aBar.mul(proofResult.eHat));
    t1.add(proofResult.d.mul(proofResult.r1Hat));

    // Bv = P1 + Q_1 * domain + sum(H_ik * msg_ik) over disclosed indexes
    ECP bv = new ECP(Bbs.P1);
    bv.add(q1.mul(domain));
    for (int k = 0; k < r; k++) {
      bv.add(hPoints.get(disclosedIndexes.get(k)).mul(disclosedScalars.get(k)));
    }

    // T2 = Bv * c + D * r3^ + sum(H_jk * m^_jk) over undisclosed indexes
    ECP t2 = bv.mul(proofResult.c);
    t2.add(proofResult.d.mul(proofResult.r3Hat));
    for (int k = 0; k < u; k++) {
      t2.add(hPoints.get(undisclosedIndexes.get(k)).mul(proofResult.commitments.get(k)));
    }

    BIG challenge =
        proofChallengeCalculate(
            proofResult.aBar,
            proofResult.bBar,
            proofResult.d,
            t1,
            t2,
            domain,
            disclosedMessages,
            disclosedIndexes,
            presentationHeader);

    if (BIG.comp(proofResult.c, challenge) != 0) return false;

    ECP2 bp2 = Bbs.g2Generator();
    ECP2 negBp2 = new ECP2(bp2);
    negBp2.neg();

    FP12 acc = PAIR.ate2(w, proofResult.aBar, negBp2, proofResult.bBar);
    acc = PAIR.fexp(acc);
    return acc.isunity();
  }

  private static BIG calculateDomain(byte[] pk, ECP q1, List<ECP> hPoints, byte[] header) {
    int l = hPoints.size();
    ByteArrayOutputStream domOcts = new ByteArrayOutputStream();
    writeBytes(domOcts, Bbs.i2osp(l, 8));
    writeBytes(domOcts, Bbs.pointToOctetsG1(q1));
    for (ECP h : hPoints) {
      writeBytes(domOcts, Bbs.pointToOctetsG1(h));
    }
    writeBytes(domOcts, Bbs.API_ID);

    ByteArrayOutputStream domInput = new ByteArrayOutputStream();
    writeBytes(domInput, pk);
    writeBytes(domInput, domOcts.toByteArray());
    writeBytes(domInput, Bbs.i2osp(header.length, 8));
    writeBytes(domInput, header);

    return Bbs.hashToScalar(domInput.toByteArray(), HASH_TO_SCALAR_DST);
  }

  private static BIG proofChallengeCalculate(
      ECP aBar,
      ECP bBar,
      ECP d,
      ECP t1,
      ECP t2,
      BIG domain,
      List<byte[]> disclosedMessages,
      List<Integer> disclosedIndexes,
      byte[] presentationHeader) {

    List<BIG> disclosedScalars = messagesToScalars(disclosedMessages);
    int r = disclosedIndexes.size();

    ByteArrayOutputStream cArr = new ByteArrayOutputStream();
    writeBytes(cArr, Bbs.i2osp(r, 8));
    for (int k = 0; k < r; k++) {
      writeBytes(cArr, Bbs.i2osp(disclosedIndexes.get(k), 8));
      writeBytes(cArr, Bbs.i2ospScalar(disclosedScalars.get(k)));
    }
    writeBytes(cArr, Bbs.pointToOctetsG1(aBar));
    writeBytes(cArr, Bbs.pointToOctetsG1(bBar));
    writeBytes(cArr, Bbs.pointToOctetsG1(d));
    writeBytes(cArr, Bbs.pointToOctetsG1(t1));
    writeBytes(cArr, Bbs.pointToOctetsG1(t2));
    writeBytes(cArr, Bbs.i2ospScalar(domain));

    ByteArrayOutputStream cOcts = new ByteArrayOutputStream();
    writeBytes(cOcts, cArr.toByteArray());
    writeBytes(cOcts, Bbs.i2osp(presentationHeader.length, 8));
    writeBytes(cOcts, presentationHeader);

    return Bbs.hashToScalar(cOcts.toByteArray(), HASH_TO_SCALAR_DST);
  }

  private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
    out.write(bytes, 0, bytes.length);
  }

  private static Signature octetsToSignature(byte[] signatureOctets)
      throws GeneralSecurityException {
    int expectedLen = Bbs.OCTET_POINT_LENGTH_G1 + Bbs.OCTET_SCALAR_LENGTH;
    if (signatureOctets.length != expectedLen) {
      throw new GeneralSecurityException("Invalid BBS signature length: " + signatureOctets.length);
    }
    byte[] aOctets = Arrays.copyOfRange(signatureOctets, 0, Bbs.OCTET_POINT_LENGTH_G1);
    ECP a = Bbs.octetsToPointG1(aOctets);
    if (a == null) {
      throw new GeneralSecurityException("Invalid BBS signature: A is not a valid G1 point");
    }
    byte[] eOctets =
        Arrays.copyOfRange(
            signatureOctets, Bbs.OCTET_POINT_LENGTH_G1, expectedLen);
    BIG e = Bbs.os2ipScalar(eOctets);
    if (!Bbs.isValidNonZeroScalar(e)) {
      throw new GeneralSecurityException("Invalid BBS signature: e is out of range");
    }
    return new Signature(a, e);
  }

  private static Proof octetsToProof(byte[] proofOctets) throws GeneralSecurityException {
    int pointLen = Bbs.OCTET_POINT_LENGTH_G1;
    int scalarLen = Bbs.OCTET_SCALAR_LENGTH;
    int proofLenFloor = 3 * pointLen + 4 * scalarLen;
    if (proofOctets.length < proofLenFloor) {
      throw new GeneralSecurityException("Invalid BBS proof: too short");
    }

    int index = 0;
    ECP[] points = new ECP[3];
    for (int i = 0; i < 3; i++) {
      byte[] pointOctets = Arrays.copyOfRange(proofOctets, index, index + pointLen);
      ECP p = Bbs.octetsToPointG1(pointOctets);
      if (p == null) {
        throw new GeneralSecurityException("Invalid BBS proof: bad G1 point at index " + i);
      }
      points[i] = p;
      index += pointLen;
    }

    List<BIG> scalars = new ArrayList<>();
    while (index < proofOctets.length) {
      if (index + scalarLen > proofOctets.length) {
        throw new GeneralSecurityException("Invalid BBS proof: truncated scalar");
      }
      byte[] scalarOctets = Arrays.copyOfRange(proofOctets, index, index + scalarLen);
      BIG s = Bbs.os2ipScalar(scalarOctets);
      if (!Bbs.isValidNonZeroScalar(s)) {
        throw new GeneralSecurityException("Invalid BBS proof: scalar out of range");
      }
      scalars.add(s);
      index += scalarLen;
    }

    if (index != proofOctets.length) {
      throw new GeneralSecurityException("Invalid BBS proof: trailing bytes");
    }
    if (scalars.size() < 4) {
      throw new GeneralSecurityException("Invalid BBS proof: not enough scalars");
    }

    BIG eHat = scalars.get(0);
    BIG r1Hat = scalars.get(1);
    BIG r3Hat = scalars.get(2);
    int j = scalars.size();
    List<BIG> commitments =
        j > 4 ? new ArrayList<>(scalars.subList(3, j - 1)) : new ArrayList<>();
    BIG c = scalars.get(j - 1);

    return new Proof(points[0], points[1], points[2], eHat, r1Hat, r3Hat, commitments, c);
  }

  private static final class Signature {
    final ECP a;
    final BIG e;

    Signature(ECP a, BIG e) {
      this.a = a;
      this.e = e;
    }
  }

  private static final class Proof {
    final ECP aBar;
    final ECP bBar;
    final ECP d;
    final BIG eHat;
    final BIG r1Hat;
    final BIG r3Hat;
    final List<BIG> commitments;
    final BIG c;

    Proof(
        ECP aBar,
        ECP bBar,
        ECP d,
        BIG eHat,
        BIG r1Hat,
        BIG r3Hat,
        List<BIG> commitments,
        BIG c) {
      this.aBar = aBar;
      this.bBar = bBar;
      this.d = d;
      this.eHat = eHat;
      this.r1Hat = r1Hat;
      this.r3Hat = r3Hat;
      this.commitments = commitments;
      this.c = c;
    }
  }
}
