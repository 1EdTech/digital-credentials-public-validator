package org.oneedtech.inspect.vc.verification;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.oneedtech.inspect.util.code.Tuple;

/**
 * Implements the functions required to verify a bbs-2023 derived (selectively-disclosed) proof,
 * https://www.w3.org/TR/vc-di-bbs/#bbs-2023-functions. These are the same "Selective Disclosure
 * Functions" (RDF Dataset Canonicalization, blank-node label replacement, mandatory/non-mandatory
 * splitting and hashing) shared with ecdsa-sd-2023 -- see {@link SDFunctions} -- parameterized here
 * for bbs-2023's always-SHA-256 hashing and its own derived proofValue CBOR layout (which, unlike
 * ecdsa-sd-2023, carries no embedded public key or per-statement signatures: BBS verifies all
 * disclosed statements together via a single ProofVerify call).
 */
public class BbsFunctions {

  private static final byte[] DERIVED_PROOF_HEADER = {(byte) 0xd9, 0x5d, 0x03};

  private final Canonicalizer canonicalizer;

  public BbsFunctions(Canonicalizer canonicalizer) {
    this.canonicalizer = canonicalizer;
  }

  public VerifyData createVerifyData(
      JsonLDObject unsecuredDocument,
      DataIntegrityProof dataIntegrityProof,
      DocumentLoader documentLoader)
      throws IOException, GeneralSecurityException, JsonLDException {

    // 1. proofHash: RDF Dataset Canonicalization (SHA-256) of the proof options.
    DataIntegrityProof proofWithoutValue =
        Bbs2023DataIntegrity.builder().base(dataIntegrityProof).defaultContexts(true).build();
    DataIntegrityProof.removeLdProofValues(proofWithoutValue);

    dataIntegrityProof.setDocumentLoader(documentLoader);
    byte[] proofHash = SHAUtil.sha256(canonicalizer.canonicalize(proofWithoutValue));

    // 2. Parse the derived proofValue: bbsProof, labelMap, mandatoryIndexes, selectiveIndexes,
    // presentationHeader.
    String proofValue = dataIntegrityProof.getProofValue();
    if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");
    DerivedProofData derivedProofData = parseDerivedProofValue(proofValue);

    // 3. labelMapFactoryFunction from the (decompressed) labelMap carried in the proof.
    Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction =
        createLabelMapFunction(derivedProofData.getLabelMap());

    // 4. Canonicalize the unsecured document with blank node labels replaced per labelMap.
    Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeJsonLd =
        labelReplacementCanonicalizeJsonLd(
            unsecuredDocument, labelMapFactoryFunction, documentLoader);
    List<String> nquads = labelReplacementCanonicalizeJsonLd.t2;

    // 5-7. Split into mandatory/non-mandatory N-Quads per mandatoryIndexes.
    List<byte[]> mandatory = new ArrayList<>();
    List<String> nonMandatory = new ArrayList<>();
    for (int index = 0; index < nquads.size(); index++) {
      String nq = nquads.get(index);
      if (derivedProofData.getMandatoryIndexes().contains(index)) {
        mandatory.add(nq.getBytes());
      } else {
        nonMandatory.add(nq);
      }
    }

    // 8. mandatoryHash.
    byte[] mandatoryHash = hashMandatoryNQuads(mandatory);

    return new VerifyData(derivedProofData, proofHash, nonMandatory, mandatoryHash);
  }

  private byte[] hashMandatoryNQuads(List<byte[]> mandatory) {
    String joinedMandatory = mandatory.stream().map(String::new).collect(Collectors.joining(""));
    return SHAUtil.sha256(joinedMandatory);
  }

  private Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeJsonLd(
      JsonLDObject unsecuredDocument,
      Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction,
      DocumentLoader documentLoader)
      throws JsonLDException, NoSuchAlgorithmException, IOException {

    unsecuredDocument.setDocumentLoader(documentLoader);
    com.apicatalog.rdf.RdfDataset rdfDataset = unsecuredDocument.toDataset();
    return labelReplacementCanonicalizeNQuads(rdfDataset, labelMapFactoryFunction);
  }

  private Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeNQuads(
      com.apicatalog.rdf.RdfDataset rdfDataset,
      Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction)
      throws IOException {

    com.apicatalog.rdf.canon.RdfCanon rdfCanon = com.apicatalog.rdf.canon.RdfCanon.create("SHA-256");
    RDFC10Canonicalizer.feedDataset(rdfDataset, rdfCanon);

    List<String[]> canonicalQuads = new ArrayList<>();
    try {
      rdfCanon.provide(
          new com.apicatalog.rdf.api.RdfQuadConsumer() {
            @Override
            public com.apicatalog.rdf.api.RdfQuadConsumer quad(
                String subject,
                String predicate,
                String object,
                String datatype,
                String language,
                String direction,
                String graph)
                throws com.apicatalog.rdf.api.RdfConsumerException {
              canonicalQuads.add(
                  new String[] {subject, predicate, object, datatype, language, direction, graph});
              return this;
            }
          });
    } catch (com.apicatalog.rdf.api.RdfConsumerException e) {
      throw new IOException("RDFC 1.0 canonicalization failed", e);
    }

    Map<String, String> canonicalIdMap =
        rdfCanon.mapping().entrySet().stream()
            .collect(
                Collectors.toMap(
                    e -> e.getKey().replaceFirst("^_:", ""),
                    e -> e.getValue().replaceFirst("^_:", "")));

    Map<String, String> labelMap = labelMapFactoryFunction.apply(canonicalIdMap);

    Map<String, String> c14nToNewLabelMap =
        labelMap.entrySet().stream()
            .collect(Collectors.toMap(e -> canonicalIdMap.get(e.getKey()), Map.Entry::getValue));

    List<String> canonicalNQuads = new ArrayList<>();
    for (String[] params : canonicalQuads) {
      String subject = replaceBlankLabel(params[0], c14nToNewLabelMap);
      String object = replaceBlankLabel(params[2], c14nToNewLabelMap);
      String graph = replaceBlankLabel(params[6], c14nToNewLabelMap);
      canonicalNQuads.add(
          com.apicatalog.rdf.nquads.NQuadsWriter.nquad(
              subject, params[1], object, params[3], params[4], params[5], graph));
    }

    // See RDFC10Canonicalizer/SDFunctions: sort after label replacement, since mandatoryIndexes
    // are positional indexes into the post-sort array.
    java.util.Collections.sort(canonicalNQuads);

    return new Tuple<>(labelMap, canonicalNQuads);
  }

  private static String replaceBlankLabel(String value, Map<String, String> c14nToLabelMap) {
    if (value != null && value.startsWith("_:")) {
      String label = c14nToLabelMap.get(value.substring(2));
      if (label != null) return "_:" + label;
    }
    return value;
  }

  private Function<Map<String, String>, Map<String, String>> createLabelMapFunction(
      Map<String, String> labelMap) {
    return canonicalIdMap -> {
      Map<String, String> bnodeIdMap = new HashMap<>();
      for (Map.Entry<String, String> entry : canonicalIdMap.entrySet()) {
        String newLabel = labelMap.get(entry.getValue());
        bnodeIdMap.put(entry.getKey(), newLabel);
      }
      return bnodeIdMap;
    };
  }

  /** Parses a bbs-2023 derived proofValue: multibase 'u' prefix, 3-byte header, CBOR components. */
  DerivedProofData parseDerivedProofValue(String proofValue) throws GeneralSecurityException {
    if (proofValue == null || proofValue.isEmpty() || proofValue.charAt(0) != 'u') {
      throw new GeneralSecurityException(
          "Invalid proofValue: must start with 'u' for multibase-base64url-no-pad encoding.");
    }

    byte[] decodedProofValue = Base64.getUrlDecoder().decode(proofValue.substring(1));

    if (decodedProofValue.length < 3
        || decodedProofValue[0] != DERIVED_PROOF_HEADER[0]
        || decodedProofValue[1] != DERIVED_PROOF_HEADER[1]
        || decodedProofValue[2] != DERIVED_PROOF_HEADER[2]) {
      throw new GeneralSecurityException(
          "Invalid proofValue: unsupported or unrecognized bbs-2023 derived proof header (only"
              + " the 'baseline' feature option is supported).");
    }

    byte[] cborBytes = new byte[decodedProofValue.length - 3];
    System.arraycopy(decodedProofValue, 3, cborBytes, 0, cborBytes.length);

    try {
      List<DataItem> decodedItems = CborDecoder.decode(cborBytes);
      if (decodedItems.isEmpty() || decodedItems.get(0).getMajorType() != MajorType.ARRAY) {
        throw new GeneralSecurityException(
            "Invalid proofValue: CBOR decoding did not return an array.");
      }
      Array decodedArray = (Array) decodedItems.get(0);
      if (decodedArray.getDataItems().size() != 5) {
        throw new GeneralSecurityException(
            "Invalid proofValue: expected a 5-element array (baseline feature option), got "
                + decodedArray.getDataItems().size());
      }
      DataItem[] components = decodedArray.getDataItems().toArray(new DataItem[0]);

      byte[] bbsProof = expectByteString(components[0], "bbsProof");

      if (components[1].getMajorType() != MajorType.MAP) {
        throw new GeneralSecurityException("Invalid proofValue: labelMap is not a map.");
      }
      Map<Integer, Integer> compressedLabelMap = new HashMap<>();
      co.nstant.in.cbor.model.Map labelMapCbor = (co.nstant.in.cbor.model.Map) components[1];
      for (DataItem key : labelMapCbor.getKeys()) {
        if (key.getMajorType() != MajorType.UNSIGNED_INTEGER) {
          throw new GeneralSecurityException("Invalid proofValue: labelMap key is not an integer.");
        }
        int intKey = ((UnsignedInteger) key).getValue().intValue();
        DataItem valueItem = labelMapCbor.get(key);
        if (valueItem.getMajorType() != MajorType.UNSIGNED_INTEGER) {
          throw new GeneralSecurityException("Invalid proofValue: labelMap value is not an integer.");
        }
        int value = ((UnsignedInteger) valueItem).getValue().intValue();
        compressedLabelMap.put(intKey, value);
      }
      Map<String, String> labelMap = decompressLabelMap(compressedLabelMap);

      List<Integer> mandatoryIndexes = expectIntArray(components[2], "mandatoryIndexes");
      List<Integer> selectiveIndexes = expectIntArray(components[3], "selectiveIndexes");
      byte[] presentationHeader = expectByteString(components[4], "presentationHeader");

      return new DerivedProofData(
          bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader);

    } catch (CborException e) {
      throw new GeneralSecurityException(
          "Invalid proofValue: CBOR decoding failed or does not match expected structure.", e);
    }
  }

  private static byte[] expectByteString(DataItem item, String name)
      throws GeneralSecurityException {
    if (item.getMajorType() != MajorType.BYTE_STRING) {
      throw new GeneralSecurityException("Invalid proofValue: " + name + " is not a byte array.");
    }
    return ((ByteString) item).getBytes();
  }

  private static List<Integer> expectIntArray(DataItem item, String name)
      throws GeneralSecurityException {
    if (item.getMajorType() != MajorType.ARRAY) {
      throw new GeneralSecurityException(
          "Invalid proofValue: " + name + " is not an array of integers.");
    }
    List<Integer> result = new ArrayList<>();
    for (DataItem element : ((Array) item).getDataItems()) {
      if (element.getMajorType() != MajorType.UNSIGNED_INTEGER) {
        throw new GeneralSecurityException(
            "Invalid proofValue: " + name + " contains a non-integer element.");
      }
      result.add(((UnsignedInteger) element).getValue().intValue());
    }
    return result;
  }

  /**
   * bbs-2023 compresses its (HMAC-shuffled) label map to plain small integers -- "c14nK" -> "bV" --
   * unlike ecdsa-sd-2023's compressLabelMap/decompressLabelMap (SDFunctions), which uses full
   * 32-byte HMAC digests as the label values. See the vc-di-bbs spec's own worked example
   * (Appendix A, "Disclosure Data"): {@code "labelMap":{"...":[["c14n0","b0"],["c14n1","b2"]]}}.
   */
  private Map<String, String> decompressLabelMap(Map<Integer, Integer> compressedLabelMap) {
    Map<String, String> map = new HashMap<>();
    for (Map.Entry<Integer, Integer> entry : compressedLabelMap.entrySet()) {
      map.put("c14n" + entry.getKey(), "b" + entry.getValue());
    }
    return map;
  }

  public static final class DerivedProofData {
    private final byte[] bbsProof;
    private final Map<String, String> labelMap;
    private final List<Integer> mandatoryIndexes;
    private final List<Integer> selectiveIndexes;
    private final byte[] presentationHeader;

    DerivedProofData(
        byte[] bbsProof,
        Map<String, String> labelMap,
        List<Integer> mandatoryIndexes,
        List<Integer> selectiveIndexes,
        byte[] presentationHeader) {
      this.bbsProof = bbsProof;
      this.labelMap = labelMap;
      this.mandatoryIndexes = mandatoryIndexes;
      this.selectiveIndexes = selectiveIndexes;
      this.presentationHeader = presentationHeader;
    }

    public byte[] getBbsProof() {
      return bbsProof;
    }

    public Map<String, String> getLabelMap() {
      return labelMap;
    }

    public List<Integer> getMandatoryIndexes() {
      return mandatoryIndexes;
    }

    public List<Integer> getSelectiveIndexes() {
      return selectiveIndexes;
    }

    public byte[] getPresentationHeader() {
      return presentationHeader;
    }
  }

  public static final class VerifyData {
    private final DerivedProofData derivedProofData;
    private final byte[] proofHash;
    private final List<String> nonMandatory;
    private final byte[] mandatoryHash;

    VerifyData(
        DerivedProofData derivedProofData,
        byte[] proofHash,
        List<String> nonMandatory,
        byte[] mandatoryHash) {
      this.derivedProofData = derivedProofData;
      this.proofHash = proofHash;
      this.nonMandatory = nonMandatory;
      this.mandatoryHash = mandatoryHash;
    }

    public DerivedProofData getDerivedProofData() {
      return derivedProofData;
    }

    public byte[] getProofHash() {
      return proofHash;
    }

    public List<String> getNonMandatory() {
      return nonMandatory;
    }

    public byte[] getMandatoryHash() {
      return mandatoryHash;
    }

    /** bbsHeader = proofHash || mandatoryHash, per the bbs-2023 Verify Derived Proof algorithm. */
    public byte[] getBbsHeader() {
      byte[] header = new byte[proofHash.length + mandatoryHash.length];
      System.arraycopy(proofHash, 0, header, 0, proofHash.length);
      System.arraycopy(mandatoryHash, 0, header, proofHash.length, mandatoryHash.length);
      return header;
    }
  }
}
