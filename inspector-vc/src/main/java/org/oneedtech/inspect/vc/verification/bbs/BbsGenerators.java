package org.oneedtech.inspect.vc.verification.bbs;

import java.util.ArrayList;
import java.util.List;

import org.miracl.core.BLS12381.ECP;

/**
 * Implements create_generators(count, api_id) from draft-irtf-cfrg-bbs-signatures Section 4.1.1:
 * a deterministic, pseudo-random sequence of G1 points derived from a fixed seed, used as the
 * BBS message generators (Q_1, H_1, ..., H_L).
 *
 * <p>Since the sequence is a deterministic function of the ciphersuite's api_id alone (it does not
 * depend on the signer's key or on the messages), and generator i only depends on generators
 * 1..i-1, results are cached and extended on demand.
 */
final class BbsGenerators {

  private static final byte[] SEED_DST = Bbs.concat(Bbs.API_ID, Bbs.bytes("SIG_GENERATOR_SEED_"));
  private static final byte[] GENERATOR_DST =
      Bbs.concat(Bbs.API_ID, Bbs.bytes("SIG_GENERATOR_DST_"));
  private static final byte[] GENERATOR_SEED =
      Bbs.concat(Bbs.API_ID, Bbs.bytes("MESSAGE_GENERATOR_SEED"));

  private static final List<ECP> CACHE = new ArrayList<>();
  private static byte[] v = Bbs.expandMessageXmd(GENERATOR_SEED, SEED_DST, Bbs.EXPAND_LEN);
  private static int nextIndex = 1;

  private BbsGenerators() {}

  /** Returns the first {@code count} generators (Q_1, H_1, ..., H_(count-1)). */
  static synchronized List<ECP> createGenerators(int count) {
    while (CACHE.size() < count) {
      byte[] indexed = Bbs.concat(v, Bbs.i2osp(nextIndex, 8));
      v = Bbs.expandMessageXmd(indexed, SEED_DST, Bbs.EXPAND_LEN);
      CACHE.add(Bbs.hashToCurveG1(v, GENERATOR_DST));
      nextIndex++;
    }
    return new ArrayList<>(CACHE.subList(0, count));
  }
}
