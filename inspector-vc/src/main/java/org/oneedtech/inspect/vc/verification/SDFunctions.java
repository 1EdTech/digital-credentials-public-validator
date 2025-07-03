package org.oneedtech.inspect.vc.verification;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.multicodec.Multicodec;
import com.apicatalog.multicodec.codec.KeyCodec;
import com.apicatalog.rdf.RdfDataset;
import com.apicatalog.rdf.RdfNQuad;
import com.apicatalog.rdf.io.nquad.NQuadsWriter;
import com.danubetech.dataintegrity.DataIntegrityProof;
import com.danubetech.dataintegrity.canonicalizer.Canonicalizer;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import io.setl.rdf.normalization.InputMappings;
import io.setl.rdf.normalization.RdfNormalizationResult;
import io.setl.rdf.normalization.RdfNormalize;
import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.bouncycastle.util.encoders.Hex;
import org.oneedtech.inspect.util.code.Tuple;

/**
 * This class implements the functions required for the ECDSA-SD 2023 signature suite,
 * https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023-functions
 */
public class SDFunctions {
  private Canonicalizer canonicalizer;
  private Multicodec codec;

  public SDFunctions(Canonicalizer canonicalizer, Multicodec codec) {
    this.canonicalizer = canonicalizer;
    this.codec = codec;
  }

  public byte[] serializeSignData(byte[] proofHash, byte[] publicKey, byte[] mandatoryHash) {
    // 1. Return the concatenation of proofHash, publicKey, and mandatoryHash, in that order, as
    // sign data.
    byte[] serializedSignData =
        new byte[proofHash.length + publicKey.length + mandatoryHash.length];
    System.arraycopy(proofHash, 0, serializedSignData, 0, proofHash.length);
    System.arraycopy(publicKey, 0, serializedSignData, proofHash.length, publicKey.length);
    System.arraycopy(
        mandatoryHash,
        0,
        serializedSignData,
        proofHash.length + publicKey.length,
        mandatoryHash.length);

    return serializedSignData;
  }

  public VerifyData createVerifyData(
      JsonLDObject unsecuredDocument,
      DataIntegrityProof dataIntegrityProof,
      DocumentLoader documentLoader)
      throws IOException, GeneralSecurityException, JsonLDException {

    // 1. Initialize proofHash to the result of perform RDF Dataset Canonicalization [RDF-CANON] on
    // the proof options. The hash used is the same as the one used in the signature algorithm,
    // i.e., SHA-256 for a P-256 curve. Note: This step can be performed in parallel; it only needs
    // to be completed before this algorithm needs to use the proofHash value.
    DataIntegrityProof proofWihoutValue =
        EcdsaSd2023DataIntegrity.builder().base(dataIntegrityProof).defaultContexts(true).build();
    DataIntegrityProof.removeLdProofValues(proofWihoutValue);

    dataIntegrityProof.setDocumentLoader(documentLoader);
    String proofHashValues = canonicalizer.canonicalize(proofWihoutValue);

    byte[] proofHash;
    if (codec == KeyCodec.P256_PUBLIC_KEY) {
      proofHash = SHAUtil.sha256(proofHashValues);
    } else if (codec == KeyCodec.P384_PUBLIC_KEY) {
      proofHash = SHAUtil.sha384(proofHashValues);
    } else {
      throw new IllegalArgumentException("Unsupported codec: " + codec);
    }

    // 2. Initialize baseSignature, publicKey, signatures, labelMap, and mandatoryIndexes, to the
    // values associated with their property names in the object returned when calling the algorithm
    // in Section 3.5.8 parseDerivedProofValue, passing proofValue from proof.
    String proofValue = dataIntegrityProof.getProofValue();
    if (proofValue == null) throw new GeneralSecurityException("No 'proofValue' in proof.");

    DisclosureData disclosureData = parseDerivedProofValue(proofValue);

    // 3. Initialize labelMapFactoryFunction to the result of calling the algorithm of Section 3.4.3
    // createLabelMapFunction.
    Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction =
        createLabelMapFunction(disclosureData.getLabelMap());

    // 4. Initialize nquads to the result of calling the algorithm of section 3.4.2
    // labelReplacementCanonicalizeJsonLd, passing document, labelMapFactoryFunction, and any custom
    // JSON-LD API options. Note: This step transforms the document into an array of canonical
    // N-Quads with pseudorandom blank node identifiers based on labelMap.
    Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeJsonLd =
        labelReplacementCanonicalizeJsonLd(
            unsecuredDocument, labelMapFactoryFunction, documentLoader);
    Map<String, String> labelMap = labelReplacementCanonicalizeJsonLd.t1;
    List<String> nquads = labelReplacementCanonicalizeJsonLd.t2;

    // 5. Initialize mandatory to an empty array.
    List<byte[]> mandatory = new ArrayList<>();

    // 6. Initialize nonMandatory to an empty array.
    List<String> nonMandatory = new ArrayList<>();

    // 7. For each entry (index, nq) in nquads, separate the N-Quads into mandatory and
    // non-mandatory categories:

    for (int index = 0; index < nquads.size(); index++) {
      String nq = nquads.get(index);

      // 7.1 If mandatoryIndexes includes index, add nq to mandatory.
      if (disclosureData.getMandatoryIndexes().contains(index)) {
        mandatory.add(nq.getBytes());
      } else {
        // 7.2 Otherwise, add nq to nonMandatory.
        nonMandatory.add(nq);
      }
    }

    // 8 Initialize mandatoryHash to the result of calling the "hashMandatory" primitive, passing
    // mandatory.
    byte[] mandatoryHash = hashMandatoryNQuads(mandatory);

    // 9 Return an object with properties matching baseSignature, proofHash, publicKey, signatures,
    // nonMandatory, and mandatoryHash.
    return new VerifyData(
        disclosureData.getBaseSignature(),
        proofHash,
        disclosureData.getPublicKey(),
        disclosureData.getSignatures(),
        nonMandatory,
        mandatoryHash);
  }

  private byte[] hashMandatoryNQuads(Collection<byte[]> mandatory) {
    // 1. Initialize bytes to the UTF-8 representation of the joined mandatory N-Quads.
    String joinedMandatory = mandatory.stream().map(String::new).collect(Collectors.joining(""));

    // 2. Initialize mandatoryHash to the result of using hasher to hash bytes.
    byte[] mandatoryHash = SHAUtil.sha256(joinedMandatory);

    // 3. Return mandatoryHash.
    return mandatoryHash;
  }

  private Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeJsonLd(
      JsonLDObject unsecuredDocument,
      Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction,
      DocumentLoader documentLoader)
      throws JsonLDException, NoSuchAlgorithmException, IOException {

    // 1. Deserialize the JSON-LD document to RDF, rdf, using the Deserialize JSON-LD to RDF
    // algorithm, passing any custom options (such as a document loader).
    unsecuredDocument.setDocumentLoader(documentLoader);
    RdfDataset rdfDataset = unsecuredDocument.toDataset();

    // 2. Serialize rdf to an array of N-Quad strings, nquads.
    // not needed becuse the canocalization algorithm will do this

    // 3. Return the result of calling the algorithm in Section 3.4.1
    // labelReplacementCanonicalizeNQuads, passing nquads, labelMapFactoryFunction, and any custom
    // options.
    return labelReplacementCanonicalizeNQuads(rdfDataset, labelMapFactoryFunction, documentLoader);
  }

  private Tuple<Map<String, String>, List<String>> labelReplacementCanonicalizeNQuads(
      RdfDataset rdfDataset,
      Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction,
      DocumentLoader documentLoader)
      throws IOException, NoSuchAlgorithmException {
    // 1. Run the RDF Dataset Canonicalization Algorithm [RDF-CANON] on the joined nquads, passing
    // any custom options, and as output, get the canonicalized dataset, which includes a canonical
    // bnode identifier map, canonicalIdMap.

    RdfNormalizationResult normalizeResult =
        RdfNormalize.normalizeFull(rdfDataset, new InputMappings(), null);
    RdfDataset canonicalizedDataset = normalizeResult.getNormalized();

    // generate a map of canonical identifiers to N-Quad strings
    // This map will be used to replace blank node identifiers in the N-Quad strings with
    // their corresponding labels from the labelMap.

    Map<String, String> canonicalIdMap =
        normalizeResult.getIssuedMappings().entrySet().stream()
            .map(e -> new Tuple<>(e.getKey().getValue(), e.getValue().getValue()))
            .map(
                t ->
                    new Tuple<>(
                        t.t1.replaceFirst("^_:", ""),
                        t.t2.replaceFirst(
                            "^_:", ""))) // ensure labels in map do not include `_:` prefix
            .collect(Collectors.toMap(t -> t.t1, t -> t.t2));

    // 2. Pass canonicalIdMap to labelMapFactoryFunction to produce a new bnode identifier map,
    // labelMap.
    Map<String, String> labelMap = labelMapFactoryFunction.apply(canonicalIdMap);

    // 3. Use the canonicalized dataset and labelMap to produce the canonical N-Quads representation
    // as an array of N-Quad strings, canonicalNQuads.
    List<String> canonicalNQuads = new ArrayList<>();

    // In this current implementation, the replacement label map is
    // replaced with one that maps the C14N labels to the new labels instead of
    // the input labels to the new labels. This is because the C14N labels are
    // already in use in the N-Quads that are updated.
    Map<String, String> c14nToNewLabelMap =
        labelMap.entrySet().stream()
            .collect(Collectors.toMap(e -> canonicalIdMap.get(e.getKey()), e -> e.getValue()));

    for (RdfNQuad nQuad : canonicalizedDataset.toList()) {
      StringWriter stringWriter = new StringWriter();
      NQuadsWriter nQuadsWriter = new NQuadsWriter(stringWriter);
      nQuadsWriter.write(nQuad);

      String canonicalNQuad = stringWriter.toString();

      List<String> nodeIds = new ArrayList<>();

      // Replace blank node identifiers in the N-Quad with their corresponding labels from labelMap.
      if (nQuad.getSubject().isBlankNode()) {
        nodeIds.add(nQuad.getSubject().getValue());
      }
      if (nQuad.getPredicate().isBlankNode()) {
        nodeIds.add(nQuad.getPredicate().getValue());
      }
      if (nQuad.getObject().isBlankNode()) {
        nodeIds.add(nQuad.getObject().getValue());
      }

      if (!nodeIds.isEmpty()) {
        for (String nodeId : nodeIds) {
          // Remove the `_:` prefix from the nodeId
          nodeId = nodeId.replaceFirst("^_:", "");
          String label = c14nToNewLabelMap.get(nodeId);
          if (label != null) {
            canonicalNQuad = canonicalNQuad.replace(nodeId, label);
          }
        }
      }

      canonicalNQuads.add(canonicalNQuad);
    }

    // 4. Return an object containing labelMap and canonicalNQuads.
    return new Tuple<>(labelMap, canonicalNQuads);
  }

  private Function<Map<String, String>, Map<String, String>> createLabelMapFunction(
      Map<String, String> labelMap) {
    // 1. Create a function, labelMapFactoryFunction, with one required input (a canonical node
    // identifier map, canonicalIdMap), that will return a blank node identifier map, bnodeIdMap, as
    // output. Set the function's implementation to:

    Function<Map<String, String>, Map<String, String>> labelMapFactoryFunction =
        canonicalIdMap -> {
          // 1.1 Generate a new empty bnode identifier map, bnodeIdMap.
          Map<String, String> bnodeIdMap = new HashMap<>();

          // 1.2 For each map entry, entry, in canonicalIdMap:
          for (Map.Entry<String, String> entry : canonicalIdMap.entrySet()) {
            // 1.2.1 Use the canonical identifier from the value in entry as a key in labelMap to
            // get
            // the new label, newLabel.
            String newLabel = labelMap.get(entry.getValue());

            // 1.2.2 Add a new entry, newEntry, to bnodeIdMap using the key from entry and newLabel
            // as
            // the value.
            bnodeIdMap.put(entry.getKey(), newLabel);
          }

          // 1.3 Return bnodeIdMap.
          return bnodeIdMap;
        };

    // 2. Return labelMapFactoryFunction.
    return labelMapFactoryFunction;
  }

  private DisclosureData parseDerivedProofValue(String proofValue) throws GeneralSecurityException {
    // 1. If the proofValue string does not start with u, indicating that it is a
    // multibase-base64url-no-pad-encoded value, an error MUST be raised and SHOULD convey an error
    // type of PROOF_VERIFICATION_ERROR.
    if (proofValue == null || proofValue.isEmpty() || proofValue.charAt(0) != 'u') {
      throw new GeneralSecurityException(
          "Invalid proofValue: must start with 'u' for multibase-base64url-no-pad encoding.");
    }

    // 2. Initialize decodedProofValue to the result of base64url-no-pad-decoding the substring
    // after the leading u in proofValue.
    byte[] decodedProofValue = Base64.getUrlDecoder().decode(proofValue.substring(1));

    // 3. If the decodedProofValue does not start with the ECDSA-SD disclosure proof header bytes
    // 0xd9, 0x5d, and 0x01, an error MUST be raised and SHOULD convey an error type of
    // PROOF_VERIFICATION_ERROR.
    if (decodedProofValue.length < 3
        || decodedProofValue[0] != (byte) 0xd9
        || decodedProofValue[1] != (byte) 0x5d
        || decodedProofValue[2] != (byte) 0x01) {
      throw new GeneralSecurityException(
          "Invalid proofValue: does not start with ECDSA-SD disclosure proof header.");
    }

    // 4. Initialize components to an array that is the result of CBOR-decoding the bytes that
    // follow the three-byte ECDSA-SD disclosure proof header. If the result is not an array of the
    // following five elements — a byte array of length 64; a byte array of length 36; an array of
    // byte arrays, each of length 64; a map of integers to byte arrays, each of length 32; and an
    // array of integers — an error MUST be raised and SHOULD convey an error type of
    // PROOF_VERIFICATION_ERROR.
    byte[] cborBytes = new byte[decodedProofValue.length - 3];
    System.arraycopy(decodedProofValue, 3, cborBytes, 0, cborBytes.length);
    try {
      List<DataItem> decodedItems = CborDecoder.decode(cborBytes);
      // Check if the decoded items is an array and has exactly 5 elements
      if (decodedItems.isEmpty() || decodedItems.get(0).getMajorType() != MajorType.ARRAY) {
        throw new GeneralSecurityException(
            "Invalid proofValue: CBOR decoding did not return an array.");
      }
      // Ensure the decoded items is an array with exactly 5 elements
      Array decodedArray = (Array) decodedItems.get(0);
      if (decodedArray.getDataItems().size() != 5) {
        throw new GeneralSecurityException(
            "Invalid proofValue: CBOR decoding did not return an array of five elements.");
      }
      DataItem[] components = decodedArray.getDataItems().toArray(new DataItem[0]);
      if (components[0].getMajorType() != MajorType.BYTE_STRING) {
        throw new GeneralSecurityException("Invalid proofValue: First element is not a byte array");
      }

      ByteString c0 = (ByteString) components[0];
      if (c0.getBytes().length != 64) {
        throw new GeneralSecurityException(
            "Invalid proofValue: First element is not a byte array of length 64.");
      }
      byte[] baseSignature = c0.getBytes();

      if (components[1].getMajorType() != MajorType.BYTE_STRING) {
        throw new GeneralSecurityException(
            "Invalid proofValue: Second element is not a byte array");
      }
      ByteString c1 = (ByteString) components[1];
      if (c1.getBytes().length != 35) { // the spec says 36, but all the example I've seen are 35
        throw new GeneralSecurityException(
            "Invalid proofValue: Second element is not a byte array of length 35.");
      }
      byte[] publicKeyBytes = c1.getBytes();

      if (components[2].getMajorType() != MajorType.ARRAY) {
        throw new GeneralSecurityException(
            "Invalid proofValue: Third element is not an array of byte arrays.");
      }

      List<byte[]> signatures = new ArrayList<>();
      Array c2 = (Array) components[2];
      for (DataItem item : c2.getDataItems()) {
        if (item.getMajorType() != MajorType.BYTE_STRING) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Third element contains an item that is not a byte array.");
        }
        ByteString byteArray = (ByteString) item;
        if (byteArray.getBytes().length != 64) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Third element contains a byte array that is not of length 64.");
        }
        signatures.add(byteArray.getBytes());
      }

      Map<Integer, byte[]> compressedLabelMap = new HashMap<>();
      if (components[3].getMajorType() != MajorType.MAP) {
        throw new GeneralSecurityException(
            "Invalid proofValue: Fourth element is not a map of integers to byte arrays.");
      }
      co.nstant.in.cbor.model.Map c3 = (co.nstant.in.cbor.model.Map) components[3];
      for (DataItem key : c3.getKeys()) {
        if (key.getMajorType() != MajorType.UNSIGNED_INTEGER) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Fourth element contains a key that is not an integer.");
        }
        int intKey = ((UnsignedInteger) key).getValue().intValue();
        DataItem value = c3.get(key);
        if (value.getMajorType() != MajorType.BYTE_STRING) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Fourth element contains a value that is not a byte array.");
        }
        ByteString byteArray = (ByteString) value;
        if (byteArray.getBytes().length != 32) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Fourth element contains a byte array that is not of length 32.");
        }
        compressedLabelMap.put(intKey, byteArray.getBytes());
      }

      List<Integer> mandatoryIndexes = new ArrayList<>();
      if (components[4].getMajorType() != MajorType.ARRAY) {
        throw new GeneralSecurityException(
            "Invalid proofValue: Fifth element is not an array of integers.");
      }
      Array c4 = (Array) components[4];
      for (DataItem item : c4.getDataItems()) {
        if (item.getMajorType() != MajorType.UNSIGNED_INTEGER) {
          throw new GeneralSecurityException(
              "Invalid proofValue: Fifth element contains an item that is not an integer.");
        }
        mandatoryIndexes.add(((UnsignedInteger) item).getValue().intValue());
      }

      // 5. Replace the fourth element in components using the result of calling the algorithm in
      // Section 3.5.6 decompressLabelMap, passing the existing fourth element of components as
      // compressedLabelMap.
      Map<String, String> labelMap = decompressLabelMap(compressedLabelMap);

      // 6. Return derived proof value as an object with properties set to the five elements, using
      // the names "baseSignature", "publicKey", "signatures", "labelMap", and "mandatoryIndexes",
      // respectively.

      return new DisclosureData(
          baseSignature, publicKeyBytes, signatures, labelMap, mandatoryIndexes);

    } catch (CborException e) {
      throw new GeneralSecurityException(
          "Invalid proofValue: CBOR decoding failed or does not match expected structure.", e);
    }
  }

  private Map<String, String> decompressLabelMap(Map<Integer, byte[]> compressedLabelMap) {

    // 1. Initialize map to an empty map.
    Map<String, String> map = new HashMap<>();

    // 2. For each entry (k, v) in compressedLabelMap:
    for (Map.Entry<Integer, byte[]> entry : compressedLabelMap.entrySet()) {
      Integer k = entry.getKey();
      byte[] v = entry.getValue();

      // 2.1 Add an entry to map with a key that adds the prefix "c14n" to k and a value that adds a
      // prefix of "u" to the base64url-no-pad-encoded value for v.
      String base64UrlEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(v);
      map.put("c14n" + k, "u" + base64UrlEncoded);
    }

    // 3. Return map as decompressed label map.
    return map;
  }

  // 2. Parse the decodedProofValue as a CBOR object.
  public class DisclosureData {
    private byte[] baseSignature;
    private byte[] publicKey;
    private List<byte[]> signatures;
    private Map<String, String> labelMap;
    private List<Integer> mandatoryIndexes;

    DisclosureData(
        byte[] baseSignature,
        byte[] publicKey,
        List<byte[]> signatures,
        Map<String, String> labelMap,
        List<Integer> mandatoryIndexes) {
      this.baseSignature = baseSignature;
      this.publicKey = publicKey;
      this.signatures = signatures;
      this.labelMap = labelMap;
      this.mandatoryIndexes = mandatoryIndexes;
    }

    public byte[] getBaseSignature() {
      return baseSignature;
    }

    public byte[] getPublicKey() {
      return publicKey;
    }

    public List<byte[]> getSignatures() {
      return signatures;
    }

    public Map<String, String> getLabelMap() {
      return labelMap;
    }

    public List<Integer> getMandatoryIndexes() {
      return mandatoryIndexes;
    }
  }

  public static class VerifyData {
    private byte[] baseSignature;
    private byte[] proofHash;
    private byte[] publicKey;

    private List<byte[]> signatures;
    private List<String> nonMandatory;
    private byte[] mandatoryHash;

    VerifyData(
        byte[] baseSignature,
        byte[] proofHash,
        byte[] publicKey,
        List<byte[]> signatures,
        List<String> nonMandatory,
        byte[] mandatoryHash) {
      this.baseSignature = baseSignature;
      this.proofHash = proofHash;
      this.publicKey = publicKey;
      this.signatures = signatures;
      this.nonMandatory = nonMandatory;
      this.mandatoryHash = mandatoryHash;
    }

    public boolean sameLength() {
      return signatures.size() == nonMandatory.size();
    }

    public byte[] getBaseSignature() {
      return baseSignature;
    }

    public byte[] getProofHash() {
      return proofHash;
    }

    public byte[] getPublicKey() {
      return publicKey;
    }

    public List<byte[]> getSignatures() {
      return signatures;
    }

    public List<String> getNonMandatory() {
      return nonMandatory;
    }

    public byte[] getMandatoryHash() {
      return mandatoryHash;
    }

    public String toString() {
      return "VerifyData{"
          + "baseSignature="
          + new String(Hex.encode(baseSignature))
          + ",\nproofHash="
          + new String(Hex.encode(proofHash))
          + ",\npublicKey="
          + new String(Hex.encode(publicKey))
          + ",\nsignatures="
          + signatures.stream()
              .map(sig -> new String(Hex.encode(sig)))
              .collect(Collectors.joining(",\n"))
          + ",\nnonMandatory="
          + nonMandatory.stream().collect(Collectors.joining(",\n "))
          + ",\nmandatoryHash="
          + new String(Hex.encode(mandatoryHash))
          + '}';
    }
  }
}
