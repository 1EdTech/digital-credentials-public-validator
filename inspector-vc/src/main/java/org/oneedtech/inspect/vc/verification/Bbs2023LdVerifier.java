package org.oneedtech.inspect.vc.verification;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import com.danubetech.dataintegrity.verifier.LdVerifier;

import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.vc.probe.EmbeddedProofModel;
import org.oneedtech.inspect.vc.probe.EmbeddedProofModelGenerator;
import org.oneedtech.inspect.vc.verification.BbsFunctions.VerifyData;
import org.oneedtech.inspect.vc.verification.bbs.BbsScheme;

/**
 * Verifies a bbs-2023 derived (selectively-disclosed) proof, https://www.w3.org/TR/vc-di-bbs/.
 *
 * <p>Only the "baseline" feature option is supported (no anonymous holder binding or
 * pseudonyms). The actual BBS cryptography (a hand-implemented port of
 * draft-irtf-cfrg-bbs-signatures over BLS12-381, since no library provides it -- see
 * {@link org.oneedtech.inspect.vc.verification.bbs}) is delegated to {@link BbsScheme}; this class
 * only handles the Data Integrity / selective-disclosure plumbing (proof parsing, RDF
 * canonicalization, mandatory/non-mandatory statement splitting), mirroring
 * {@link EcdsaSd2023LdVerifier}.
 */
public class Bbs2023LdVerifier extends LdVerifier<Bbs2023SignatureSuite>
    implements EmbeddedProofModelGenerator {

  private final byte[] publicKey;

  private EmbeddedProofModel model;

  public Bbs2023LdVerifier(byte[] publicKey) {
    super(SignatureSuites.SIGNATURE_SUITE_BBS_2023, null);
    this.publicKey = publicKey;
  }

  public Canonicalizer getCanonicalizer(DataIntegrityProof dataIntegrityProof) {
    return new RDFC10Canonicalizer();
  }

  public boolean verify(JsonLDObject jsonLdObject, DataIntegrityProof dataIntegrityProof)
      throws IOException, GeneralSecurityException, JsonLDException {

    model = new EmbeddedProofModel();

    JsonLDObject unsecuredDocument = JsonLDObject.builder().base(jsonLdObject).build();
    DataIntegrityProof.removeFromJsonLdObject(unsecuredDocument);
    model.addIntermediateValue("unsecuredDocument", unsecuredDocument.toJson(true));

    BbsFunctions bbsFunctions = new BbsFunctions(getCanonicalizer(dataIntegrityProof));
    VerifyData verifyData =
        bbsFunctions.createVerifyData(
            unsecuredDocument, dataIntegrityProof, jsonLdObject.getDocumentLoader());

    model.addIntermediateValue("proofHash", Hex.toHexString(verifyData.getProofHash()));
    model.addIntermediateValue("mandatoryHash", Hex.toHexString(verifyData.getMandatoryHash()));
    model.addIntermediateValue("bbsHeader", Hex.toHexString(verifyData.getBbsHeader()));
    model.addIntermediateValue(
        "nonMandatory", String.join(",\n", verifyData.getNonMandatory()));
    model.addIntermediateValue(
        "mandatoryIndexes",
        verifyData.getDerivedProofData().getMandatoryIndexes().stream()
            .map(String::valueOf)
            .collect(Collectors.joining(", ")));
    model.addIntermediateValue(
        "selectiveIndexes",
        verifyData.getDerivedProofData().getSelectiveIndexes().stream()
            .map(String::valueOf)
            .collect(Collectors.joining(", ")));
    model.addIntermediateValue(
        "presentationHeader",
        Hex.toHexString(verifyData.getDerivedProofData().getPresentationHeader()));

    List<byte[]> disclosedMessages =
        verifyData.getNonMandatory().stream().map(s -> s.getBytes(UTF_8)).collect(Collectors.toList());

    boolean verified =
        BbsScheme.proofVerify(
            publicKey,
            verifyData.getDerivedProofData().getBbsProof(),
            verifyData.getBbsHeader(),
            verifyData.getDerivedProofData().getPresentationHeader(),
            disclosedMessages,
            verifyData.getDerivedProofData().getSelectiveIndexes());

    model.addIntermediateValue("verified", Boolean.toString(verified));

    return verified;
  }

  @Override
  public boolean verify(byte[] signingInput, DataIntegrityProof dataIntegrityProof)
      throws GeneralSecurityException {
    throw new UnsupportedOperationException("Verification not supported for BBS 2023 LD Verifier");
  }

  @Override
  public EmbeddedProofModel getGeneratedObject() {
    return model;
  }
}
