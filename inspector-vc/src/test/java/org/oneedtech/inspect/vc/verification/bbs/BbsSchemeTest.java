package org.oneedtech.inspect.vc.verification.bbs;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Validates {@link BbsScheme#verify} and {@link BbsScheme#proofVerify} against the official
 * test vectors published by the IETF BBS signature scheme draft
 * (draft-irtf-cfrg-bbs-signatures-06, ciphersuite BLS12-381-SHA-256), as mirrored at
 * https://github.com/decentralized-identity/bbs-signature/tree/main/tooling/fixtures/fixture_data/bls12-381-sha-256
 *
 * <p>These vectors are the primary correctness gate for this hand-implemented BBS/pairing code:
 * there is no signer/prover in this codebase to round-trip against, so trust instead comes from
 * matching independently-produced, spec-conformant signatures and proofs.
 */
class BbsSchemeTest {

  private static final String PK =
      "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60"
          + "268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55"
          + "ded0c";
  private static final String HEADER = "11223344556677889900aabbccddeeff";
  private static final String PRESENTATION_HEADER =
      "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501";

  private static final String[] MESSAGES_10 = {
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    ""
  };

  private static byte[] h(String hex) {
    return Bbs.hexToBytes(hex);
  }

  @Test
  void validSingleMessageSignature() throws GeneralSecurityException {
    List<byte[]> messages =
        List.of(h("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"));
    String signature =
        "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f"
            + "27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0";

    assertTrue(BbsScheme.verify(h(PK), h(signature), h(HEADER), messages));
  }

  @Test
  void invalidSignatureExtraUnsignedMessage() throws GeneralSecurityException {
    // Same signature as validSingleMessageSignature, but verified against 2 messages instead of 1.
    List<byte[]> messages =
        List.of(
            h("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
            h("c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80"));
    String signature =
        "84773160b824e194073a57493dac1a20b667af70cd2352d8af241c77658da5253aa8458317cca0eae615690d55b1f"
            + "27164657dcafee1d5c1973947aa70e2cfbb4c892340be5969920d0916067b4565a0";

    assertFalse(BbsScheme.verify(h(PK), h(signature), h(HEADER), messages));
  }

  @Test
  void validMultiMessageSignature() throws GeneralSecurityException {
    List<byte[]> messages = List.of(h(MESSAGES_10[0]), h(MESSAGES_10[1]), h(MESSAGES_10[2]),
        h(MESSAGES_10[3]), h(MESSAGES_10[4]), h(MESSAGES_10[5]), h(MESSAGES_10[6]),
        h(MESSAGES_10[7]), h(MESSAGES_10[8]), h(MESSAGES_10[9]));
    String signature =
        "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8"
            + "ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8";

    assertTrue(BbsScheme.verify(h(PK), h(signature), h(HEADER), messages));
  }

  @Test
  void validSingleMessageRevealedProof() throws GeneralSecurityException {
    List<byte[]> disclosed =
        List.of(h("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"));
    String proof =
        "94916292a7a6bade28456c601d3af33fcf39278d6594b467e128a3f83686a104ef2b2fcf72df0215eeaf69262ffe81"
            + "94a19fab31a82ddbe06908985abc4c9825788b8a1610942d12b7f5debbea8985296361206dbace7af0cc834c80f3"
            + "3e0aadaeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd3"
            + "7b506830a49f21d592f5e634f47cee05a025a2f8f94e73a6c15f02301d1178a92873b6e8634bafe4983c3e15a663d"
            + "64080678dbf29417519b78af042be2b3e1c4d08b8d520ffab008cbaaca5671a15b22c239b38e940cfeaa5e7210457"
            + "6a9ec4a6fad78c532381aeaa6fb56409cef56ee5c140d455feeb04426193c57086c9b6d397d9418";

    assertTrue(
        BbsScheme.proofVerify(
            h(PK), h(proof), h(HEADER), h(PRESENTATION_HEADER), disclosed, List.of(0)));
  }

  @Test
  void validMultiMessagePartialRevealProof() throws GeneralSecurityException {
    List<byte[]> disclosed =
        List.of(h(MESSAGES_10[0]), h(MESSAGES_10[2]), h(MESSAGES_10[4]), h(MESSAGES_10[6]));
    String proof = derivedProofHex();

    assertTrue(
        BbsScheme.proofVerify(
            h(PK), h(proof), h(HEADER), h(PRESENTATION_HEADER), disclosed, List.of(0, 2, 4, 6)));
  }

  @Test
  void invalidProofWrongPresentationHeader() throws GeneralSecurityException {
    List<byte[]> disclosed =
        List.of(h(MESSAGES_10[0]), h(MESSAGES_10[2]), h(MESSAGES_10[4]), h(MESSAGES_10[6]));
    String wrongPh = "011594ba7f95b3b470ea4102dd5899de3a042e5104d3ea01d15e6780d831d2be";

    assertFalse(
        BbsScheme.proofVerify(
            h(PK), h(derivedProofHex()), h(HEADER), h(wrongPh), disclosed, List.of(0, 2, 4, 6)));
  }

  @Test
  void invalidProofWrongPublicKey() {
    String wrongPk =
        "b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ff"
            + "b104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b9"
            + "4d41c6";
    List<byte[]> disclosed =
        List.of(h(MESSAGES_10[0]), h(MESSAGES_10[2]), h(MESSAGES_10[4]), h(MESSAGES_10[6]));

    assertFalse(
        assertDoesNotThrow(
            () ->
                BbsScheme.proofVerify(
                    h(wrongPk),
                    h(derivedProofHex()),
                    h(HEADER),
                    h(PRESENTATION_HEADER),
                    disclosed,
                    List.of(0, 2, 4, 6))));
  }

  @Test
  void invalidProofModifiedMessage() {
    // message[0] changed from the value actually signed.
    List<byte[]> disclosed =
        List.of(
            h(
                "7385ee1a722e00e173b4cdb1c1e0c3fb379403a31b337d3778c447d9da664ac876b0f7c5587d9e994c51f9e2b"
                    + "6de09c0f1d0f3b39b275a96da4926c22e55166998b8c4e90372820c007ceb27bd34ec4ebfab63fea4dcc88d9"
                    + "5f58b25ffd35b041f3fe994"),
            h(MESSAGES_10[2]),
            h(MESSAGES_10[4]),
            h(MESSAGES_10[6]));

    assertFalse(
        assertDoesNotThrow(
            () ->
                BbsScheme.proofVerify(
                    h(PK),
                    h(derivedProofHex()),
                    h(HEADER),
                    h(PRESENTATION_HEADER),
                    disclosed,
                    List.of(0, 2, 4, 6))));
  }

  private static String derivedProofHex() {
    return "a2ed608e8e12ed21abc2bf154e462d744a367c7f1f969bdbf784a2a134c7db2d340394223a5397a3011b1c340ebc41"
        + "5199462ba6f31106d8a6da8b513b37a47afe93c9b3474d0d7a354b2edc1b88818b063332df774c141f7a07c48fe50d4"
        + "52f897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac4"
        + "81356918cd38025d86b28650e909defe9604a7259f44386b861608be742af7775a2e71a6070e5836f5f54dc43c60096"
        + "834a5b6da295bf8f081f72b7cdf7f3b4347fb3ff19edaa9e74055c8ba46dbcb7594fb2b06633bb5324192eb9be91be0d"
        + "33e453b4d3127459de59a5e2193c900816f049a02cb9127dac894418105fa1641d5a206ec9c42177af9316f43341744"
        + "1478276ca0303da8f941bf2e0222a43251cf5c2bf6eac1961890aa740534e519c1767e1223392a3a286b0f4d91f7f252"
        + "17a7862b8fcc1810cdcfddde2a01c80fcc90b632585fec12dc4ae8fea1918e9ddeb9414623a457e88f53f545841f9d5d"
        + "cb1f8e160d1560770aa79d65e2eca8edeaecb73fb7e995608b820c4a64de6313a370ba05dc25ed7c1d18519208496365"
        + "2f2870341bdaa4b1a37f8c06348f38a4f80c5a2650a21d59f09e8305dcd3fc3ac30e2a";
  }
}
