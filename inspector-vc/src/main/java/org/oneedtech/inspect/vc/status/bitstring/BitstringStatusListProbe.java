package org.oneedtech.inspect.vc.status.bitstring;

import com.apicatalog.multibase.MultibaseDecoder;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.zip.GZIPInputStream;
import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.MimeType;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.BitstringStatusListCredentialInspector;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.probe.RunContextKey;

/**
 * Follows algorithm defined at https://w3c.github.io/vc-bitstring-status-list/#validate-algorithm
 */
public class BitstringStatusListProbe extends Probe<JsonNode> {

  @Override
  public ReportItems run(JsonNode credentialStatus, RunContext ctx) {
    // 2. Let minimumNumberOfEntries be 131,072 unless a different lower bound is established by a
    // specific ecosystem specification.
    int minimumNumberOfEntries = 131_072;

    // 3. Let status purpose be the value of statusPurpose in the credentialStatus entry in the
    // credentialToValidate.
    String statusPurpose = credentialStatus.get("statusPurpose").asText().strip();

    int statusSize =
        credentialStatus.hasNonNull("statusSize")
            ? credentialStatus.get("statusSize").asInt()
            : 1; // indicates the size of the status entry in bits
    if (statusSize < 0) {
      return error("statusSize must be a non-negative integer", ctx);
    }

    // 4. Dereference the statusListCredential URL, and ensure that all proofs verify successfully
    URI statusListCredentialUrl;
    try {
      statusListCredentialUrl = new URI(credentialStatus.get("statusListCredential").asText());
    } catch (Exception e) {
      return error("statusListCredential is not a valid URI", ctx);
    }
    UriResource uriResource =
        new UriResource(statusListCredentialUrl, null, List.of(MimeType.JSON, MimeType.JSON_LD));

    BitstringStatusListCredentialInspector inspector =
        new BitstringStatusListCredentialInspector.Builder()
            .inject(RunContextKey.DID_RESOLVER, ctx.get(RunContextKey.DID_RESOLVER))
            .build();

    Report report = inspector.run(uriResource);
    if (report.getOutcome() != Outcome.VALID) {
      // the credential is not valid, return inspector report
      return new ReportItems(report);
    }

    Optional<VerifiableCredential> statusListCredentialMaybe =
        report.getGeneratedObject(VerifiableCredential.ID);
    if (statusListCredentialMaybe.isEmpty()) {
      return exception("BitstringStatusListCredential not found in report", uriResource);
    }
    VerifiableCredential statusListCredential = statusListCredentialMaybe.get();

    // 5. Verify that the status purpose is equal to a statusPurpose value in the
    // statusListCredential.
    JsonNode credentialSubject = statusListCredential.getJson().get("credentialSubject");
    if (!credentialSubject.get("statusPurpose").asText().strip().equals(statusPurpose)) {
      return error(
          "statusPurpose mismatch (credential: "
              + statusPurpose
              + ", bitstringStatusListCredential: "
              + credentialSubject.get("statusPurpose").asText().strip(),
          ctx);
    }

    // 6. Let compressed bitstring be the value of the encodedList property of the
    // BitstringStatusListCredential.
    String encodedList = credentialSubject.get("encodedList").asText();
    if (encodedList == null || encodedList.isEmpty()) {
      return error("encodedList is empty", ctx);
    }

    // 7. Let credentialIndex be the value of the statusListIndex property of the
    // BitstringStatusListEntry.
    int credentialIndex = credentialStatus.get("statusListIndex").asInt();

    // 8. Generate a revocation bitstring by passing compressed bitstring to the Bitstring Expansion
    // Algorithm.
    try {
      byte[] revocationBitString = expand(encodedList);

      // 9. If the length of the revocation bitstring divided by statusSize is less than
      // minimumNumberOfEntries, raise a STATUS_LIST_LENGTH_ERROR.
      if ((revocationBitString.length * 8 / statusSize) < minimumNumberOfEntries) {
        return error("revocation bitstring length is less than minimumNumberOfEntries", ctx);
      }

      // 10. Let status be the value in the bitstring at the position indicated by the
      // credentialIndex
      // multiplied by the size. If the credentialIndex multiplied by the size is a value outside of
      // the range of the bitstring, a RANGE_ERROR MUST be raised.
      int index = credentialIndex * statusSize;
      if (index >= revocationBitString.length) {
        return error(
            "credentialIndex multiplied by the size is a value outside of the range of the"
                + " bitstring",
            ctx);
      }
      int byteIndex = index / 8; // Find the byte index
      int bitPosition = index % 8; // Find the bit within the byte
      byte byteValue = revocationBitString[byteIndex];

      // printl bytevalue in hexadecimal
      System.out.println("Byte value in hexadecimal: " + Integer.toHexString(byteValue));
      // find the position in revocationBitString where its value is different than zero and print
      // it
      for (int i = 0; i < revocationBitString.length; i++) {
        if (revocationBitString[i] != 0) {
          System.out.println(
              "Position in revocationBitString where its value is different than zero: "
                  + i
                  + " = "
                  + revocationBitString[i]);
          break;
        }
      }

      // Calculate the mask for the bit we are interested in
      int bitMask = 1 << (7 - bitPosition); // Left-to-right indexing (MSB is 0th bit)
      // Check if the bit is set (non-zero value)
      if ((byteValue & bitMask) != 0) {
        return fatal("Credential has been revoked", ctx);
      }
      return success(ctx);

    } catch (IOException e) {
      return fatal("Error expanding bitstring:" + e.getLocalizedMessage(), ctx);
    }
  }

  private byte[] expand(String encodedList) throws IOException {

    // 2. Generate an uncompressed bitstring by using the Multibase-decode algorithm on the
    // compressed bitstring and
    // then expanding the output using the GZIP decompression algorithm [RFC1952].
    byte[] decodedBitstring = MultibaseDecoder.getInstance().decode(encodedList);

    // ungzip decodedBitstring
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(decodedBitstring);
    GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream);
    byte[] buffer = new byte[1024];
    int bytesRead;
    ByteArrayOutputStream decompressedStream = new ByteArrayOutputStream();
    while ((bytesRead = gzipInputStream.read(buffer)) != -1) {
      decompressedStream.write(buffer, 0, bytesRead);
    }
    return decompressedStream.toByteArray();
  }

  public static final String ID = BitstringStatusListProbe.class.getSimpleName();
}
