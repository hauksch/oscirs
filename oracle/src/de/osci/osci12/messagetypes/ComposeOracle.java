package de.osci.osci12.messagetypes;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

/**
 * Compose-oracle for the chunked-send differential (issue #8 handoff):
 * drives the REAL 2.6.1 reference library to serialize a signed
 * (optionally transport-encrypted) PartialStoreDelivery with
 * deterministic inputs, returning the complete wire stream.
 *
 * Lives in the {@code de.osci.osci12.messagetypes} package on purpose:
 * the reference's serialization entry points ({@code sign()},
 * {@code writeXML(OutputStream)}, {@code SOAPMessageEncrypted}) are
 * package-private, and the oracle must reproduce exactly what
 * {@code transmit()} writes - signature first, then the (optional)
 * encrypted envelope.
 *
 * Wire inputs (fixed on both sides, oscirs composes the identical
 * message):
 * <pre>
 *   ConversationId  1516031926756497464904932674077  (digits, osci:Number)
 *   SequenceNumber  0
 *   Challenge       b64("Y2hhbGxlbmdl")
 *   Response        b64("cmVzcG9uc2U=")
 *   MessageId       b64("bXNn")
 *   Subject         "S"
 *   ChunkInformation ChunkNumber=1 ChunkSize=64
 *                    TotalChunkNumbers=2 TotalMessageSize=128
 *   Blob            64 bytes of 'A', Content-ID ChunkBlobStoreDelivery
 *   NIC             CipherCertificateOriginator  (alice cipher)
 *                   CipherCertificateAddressee   (bob cipher)
 *                   SignatureCertificateOriginator (alice signature)
 *   FeatureDescription the six OSCIFeatures (reference defaults)
 * </pre>
 *
 * mode: {@code encrypt=false} writes the signed partial (plain writeXML);
 * {@code encrypt=true} wraps it into the SOAPMessageEncrypted transport
 * envelope to the intermediary's cipher certificate (the corpus manager
 * key, which the Rust side holds for decryption).
 */
public final class ComposeOracle {

  private static final String KEYSTORE_PASSWORD = "123456";

  private ComposeOracle() {}

  public static byte[] composePartial(String corpus, boolean encrypt) throws Exception {
    // roles from the corpus keystores (password 123456 everywhere)
    de.osci.osci12.roles.Originator originator = new de.osci.osci12.roles.Originator(
        new de.osci.osci12.samples.impl.crypto.PKCS12Signer(
            Files.newInputStream(Paths.get(corpus, "certs", "alice_signature_4096.p12")),
            KEYSTORE_PASSWORD),
        new de.osci.osci12.samples.impl.crypto.PKCS12Decrypter(
            Files.newInputStream(Paths.get(corpus, "certs", "carol_cipher_4096.p12")),
            KEYSTORE_PASSWORD));
    X509Certificate intermedCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "osci_manager_cipher_4096.cer")));
    X509Certificate bobCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "bob_cipher_4096.cer")));
    de.osci.osci12.roles.Intermed intermed = new de.osci.osci12.roles.Intermed(
        null, intermedCipherCert, new java.net.URI("http://localhost/osci"));
    de.osci.osci12.roles.Addressee addressee =
        new de.osci.osci12.roles.Addressee(null, bobCipherCert);

    de.osci.osci12.common.DialogHandler dialog =
        new de.osci.osci12.common.DialogHandler(
            originator, intermed, new NullTransport());
    dialog.setLanguageList("de");
    dialog.setCreateSignatures(true);
    dialog.setEncryption(encrypt);

    // deterministic pre-dialog state
    de.osci.osci12.soapheader.ControlBlockH pre = dialog.getControlblock();
    pre.setChallenge(
        Base64.getEncoder().encodeToString("Y2hhbGxlbmdl".getBytes(StandardCharsets.UTF_8)));

    // the FeatureDescription the reference client declares: the six
    // OSCIFeatures (dialogHandler builds it - verify and keep whatever it
    // carries; isSendFeatureDescription defaults true so it is written)
    de.osci.osci12.messageparts.ChunkInformation chunkInfo =
        new de.osci.osci12.messageparts.ChunkInformation(64L, 1, 128L, 2);

    PartialStoreDelivery partial = new PartialStoreDelivery(
        dialog, addressee, chunkInfo,
        Base64.getEncoder().encodeToString("bXNn".getBytes(StandardCharsets.UTF_8)));
    partial.setSubject("S");
    byte[] blob = new byte[64];
    Arrays.fill(blob, (byte) 'A');
    partial.setChunkBlob(new java.io.ByteArrayInputStream(blob));

    // the partial ctor mutates the LIVE control block (resetControlBlock
    // replaces the instance for implicit dialogs, then Response = previous
    // Challenge, Challenge = random, SequenceNumber += 1) - re-pin the
    // fixed values on the LIVE instance so both sides compose identical
    // control blocks
    de.osci.osci12.soapheader.ControlBlockH cb = dialog.getControlblock();
    cb.setConversationID("1516031926756497464904932674077");
    cb.setSequenceNumber(0);
    // raw values: ControlBlockH.writeXML writes them verbatim (matching
    // oscirs, which writes the given strings unencoded)
    cb.setChallenge("Y2hhbGxlbmdl");
    cb.setResponse("cmVzcG9uc2U=");

    // sign() is package-private (declared in OSCIMessage, overridden in
    // StoreDelivery) - same-package here, called directly; this is
    // exactly what transmit() does before writing
    partial.sign();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    if (encrypt) {
      SOAPMessageEncrypted envelope = new SOAPMessageEncrypted(partial, null);
      envelope.writeXML(out);
    } else {
      partial.writeXML(out);
    }
    return out.toByteArray();
  }

  /**
   * Full-delivery compose oracle (rosci chunked-send handoff): the
   * manager reassembles the chunk blobs into the complete
   * StoreDelivery wire stream - which on rosci's stack is written by
   * oscirs. This drives the REAL 2.6.1 library to serialize the same
   * full delivery (signed, one ContentContainer whose Content
   * references a large binary attachment, deterministic control block
   * and content bytes incl. embedded boundary-lookalike sequences) so
   * the Rust test can diff the MIME framing byte-for-byte.
   *
   * mode: unused for now (the plain signed delivery is what gets
   * chunked; transport encryption wraps it identically to the partial).
   */
  public static byte[] composeDelivery(String corpus) throws Exception {
    de.osci.osci12.roles.Originator originator = new de.osci.osci12.roles.Originator(
        new de.osci.osci12.samples.impl.crypto.PKCS12Signer(
            Files.newInputStream(Paths.get(corpus, "certs", "alice_signature_4096.p12")),
            KEYSTORE_PASSWORD),
        new de.osci.osci12.samples.impl.crypto.PKCS12Decrypter(
            Files.newInputStream(Paths.get(corpus, "certs", "carol_cipher_4096.p12")),
            KEYSTORE_PASSWORD));
    X509Certificate intermedCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "osci_manager_cipher_4096.cer")));
    X509Certificate bobCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "bob_cipher_4096.cer")));
    de.osci.osci12.roles.Intermed intermed = new de.osci.osci12.roles.Intermed(
        null, intermedCipherCert, new java.net.URI("http://localhost/osci"));
    de.osci.osci12.roles.Addressee addressee =
        new de.osci.osci12.roles.Addressee(null, bobCipherCert);

    de.osci.osci12.common.DialogHandler dialog =
        new de.osci.osci12.common.DialogHandler(originator, intermed, new NullTransport());
    dialog.setLanguageList("de");
    dialog.setCreateSignatures(true);
    dialog.setEncryption(false);

    de.osci.osci12.soapheader.ControlBlockH pre = dialog.getControlblock();
    pre.setChallenge(
        Base64.getEncoder().encodeToString("Y2hhbGxlbmdl".getBytes(StandardCharsets.UTF_8)));

    // deterministic 300_001-byte binary content (multiple-of-3 edge plus
    // padding char) with an embedded boundary-lookalike sequence
    byte[] blob = new byte[300_001];
    Arrays.fill(blob, (byte) 'A');
    byte[] lookalike = "\r\n--MIME_boundary\r\nContent-Type: text/xml".getBytes(StandardCharsets.UTF_8);
    System.arraycopy(lookalike, 0, blob, 150_000, Math.min(lookalike.length, blob.length - 150_000));

    de.osci.osci12.messageparts.Attachment attachment =
        new de.osci.osci12.messageparts.Attachment(
            new java.io.ByteArrayInputStream(blob), "ChunkBlobStoreDelivery");
    de.osci.osci12.messageparts.ContentContainer container =
        new de.osci.osci12.messageparts.ContentContainer();
    de.osci.osci12.messageparts.Content content =
        new de.osci.osci12.messageparts.Content(attachment);
    container.addContent(content);

    StoreDelivery delivery =
        new StoreDelivery(dialog, addressee,
            Base64.getEncoder().encodeToString("bXNn".getBytes(StandardCharsets.UTF_8)));
    delivery.setSubject("S");
    delivery.addContentContainer(container);

    // the ctor re-randomizes the control block - re-pin the fixed values
    de.osci.osci12.soapheader.ControlBlockH cb = dialog.getControlblock();
    cb.setConversationID("1516031926756497464904932674077");
    cb.setSequenceNumber(1);
    // raw values: ControlBlockH.writeXML writes them verbatim (matching
    // oscirs, which writes the given strings unencoded)
    cb.setChallenge("Y2hhbGxlbmdl");
    cb.setResponse("cmVzcG9uc2U=");

    delivery.sign();

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    delivery.writeMessage(out);
    return out.toByteArray();
  }

  /** Transport placeholder - never used (nothing is transmitted). */
  private static final class NullTransport
      implements de.osci.osci12.extinterfaces.TransportI {
    @Override
    public String getVersion() {
      return "oracle-null";
    }

    @Override
    public String getVendor() {
      return "osci-rust-rewrite";
    }

    @Override
    public de.osci.osci12.extinterfaces.TransportI newInstance() {
      return new NullTransport();
    }

    @Override
    public InputStream getResponseStream() {
      return new java.io.ByteArrayInputStream(new byte[0]);
    }

    @Override
    public boolean isOnline(java.net.URI uri) {
      return false;
    }

    @Override
    public long getContentLength() {
      return -1;
    }

    @Override
    public ByteArrayOutputStream getConnection(java.net.URI uri, long length) {
      return new ByteArrayOutputStream();
    }
  }

  /**
   * Full in-vitro chunked exchange (the live 9400 handoff): drives the
   * REAL 2.6.1 library through the sanctioned flow of the reference
   * sample (InitDialog -> GetMessageId -> PartialStoreDelivery x N ->
   * ExitDialog, one explicit dialog) against a scripted transport that
   * synthesizes the manager's responses (control block answers the
   * request challenge, echoes sequence + conversation, fresh challenge,
   * ReceivedChunks echo) and records every request/response stream.
   *
   * Writes into {@code outDir}: {@code report.txt} (the per-exchange
   * dialog-state table - the known-good exchange-by-exchange reference
   * for the live diff) plus {@code reqN-<kind>.osci} /
   * {@code respN-<kind>.osci} wire streams.
   */
  public static void chunkedExchange(String corpus, String outDir) throws Exception {
    Files.createDirectories(Paths.get(outDir));
    de.osci.osci12.roles.Originator originator = new de.osci.osci12.roles.Originator(
        new de.osci.osci12.samples.impl.crypto.PKCS12Signer(
            Files.newInputStream(Paths.get(corpus, "certs", "alice_signature_4096.p12")),
            KEYSTORE_PASSWORD),
        new de.osci.osci12.samples.impl.crypto.PKCS12Decrypter(
            Files.newInputStream(Paths.get(corpus, "certs", "carol_cipher_4096.p12")),
            KEYSTORE_PASSWORD));
    X509Certificate intermedCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "osci_manager_cipher_4096.cer")));
    X509Certificate bobCipherCert = de.osci.helper.Tools.createCertificate(
        Files.newInputStream(Paths.get(corpus, "certs", "bob_cipher_4096.cer")));
    de.osci.osci12.roles.Intermed intermed = new de.osci.osci12.roles.Intermed(
        null, intermedCipherCert, new java.net.URI("http://localhost/osci"));
    de.osci.osci12.roles.Addressee addressee =
        new de.osci.osci12.roles.Addressee(null, bobCipherCert);

    // manager-side handler for response composition (roles are only
    // composition inputs; responses are written unsigned)
    de.osci.osci12.common.DialogHandler manager = new de.osci.osci12.common.DialogHandler(
        originator, intermed, new NullTransport());
    manager.setCreateSignatures(false);

    RecordingTransport transport = new RecordingTransport(outDir, manager);
    de.osci.osci12.common.DialogHandler dialog = new de.osci.osci12.common.DialogHandler(
        originator, intermed, transport);
    dialog.setLanguageList("de");
    dialog.setCreateSignatures(true);
    dialog.setEncryption(false);

    new InitDialog(dialog).send();
    ResponseToGetMessageId rsp2GetMsgId = new GetMessageId(dialog).send();
    String oscid = rsp2GetMsgId.getMessageId();

    // the full delivery on a THROWAWAY dialog (the sample's
    // strDelDialog) - ~2.4MB payload so 1000KB chunking yields 3 chunks
    de.osci.osci12.common.DialogHandler strDel = new de.osci.osci12.common.DialogHandler(
        originator, intermed, new NullTransport());
    strDel.setCreateSignatures(true);
    StoreDelivery full = new StoreDelivery(strDel, addressee, oscid);
    full.setSubject("S");
    de.osci.osci12.messageparts.ContentContainer coco =
        new de.osci.osci12.messageparts.ContentContainer();
    byte[] blob = new byte[2_500_000];
    Arrays.fill(blob, (byte) 'A');
    byte[] lookalike = "\r\n--MIME_boundary\r\nContent-Type: text/xml"
        .getBytes(StandardCharsets.UTF_8);
    System.arraycopy(lookalike, 0, blob, 1_200_000, lookalike.length);
    de.osci.osci12.messageparts.Attachment fullAtt =
        new de.osci.osci12.messageparts.Attachment(
            new java.io.ByteArrayInputStream(blob), "FullBlob");
    coco.addContent(new de.osci.osci12.messageparts.Content(fullAtt));
    full.addContentContainer(coco);
    ByteArrayOutputStream fullOut = new ByteArrayOutputStream();
    full.writeMessage(fullOut);
    byte[] fullBytes = fullOut.toByteArray();

    // 1000KB chunks (the sample's convention: ChunkInformation in KB)
    long chunkSizeKB = 1000;
    long chunkSizeBytes = chunkSizeKB * 1024;
    int totalChunks = (int) ((fullBytes.length + chunkSizeBytes - 1) / chunkSizeBytes);
    long totalKB = fullBytes.length / 1024;
    transport.report("full delivery: " + fullBytes.length + " bytes -> " + totalChunks
        + " chunks of <= " + chunkSizeKB + "KB, TotalMessageSize=" + totalKB + " (KB)");
    transport.report("");
    for (int i = 1; i <= totalChunks; i++) {
      int from = (int) ((i - 1) * chunkSizeBytes);
      int to = (int) Math.min(fullBytes.length, i * chunkSizeBytes);
      byte[] chunk = Arrays.copyOfRange(fullBytes, from, to);
      de.osci.osci12.messageparts.ChunkInformation ci =
          new de.osci.osci12.messageparts.ChunkInformation(chunkSizeKB, i, totalKB, totalChunks);
      PartialStoreDelivery partial = new PartialStoreDelivery(dialog, addressee, ci, oscid);
      partial.setChunkBlob(new java.io.ByteArrayInputStream(chunk));
      ResponseToPartialStoreDelivery rsp = partial.send();
      String code = rsp.getFeedback()[0][1];
      transport.report("client after chunk " + i + ": feedback=" + code);
    }
    new ExitDialog(dialog).send();
    transport.report("exchange complete: " + transport.round + " round trips");
    Files.write(Paths.get(outDir, "report.txt"), transport.report.toString().getBytes(
        StandardCharsets.UTF_8));
  }

  /** Scripted manager: captures each request, synthesizes the response. */
  private static final class RecordingTransport
      implements de.osci.osci12.extinterfaces.TransportI {
    private final String outDir;
    private final de.osci.osci12.common.DialogHandler manager;
    private final StringBuilder report = new StringBuilder();
    private final CapturingStream capture = new CapturingStream();
    private byte[] response = new byte[0];
    private int round = 0;
    private String conversationId = null;

    RecordingTransport(String outDir, de.osci.osci12.common.DialogHandler manager) {
      this.outDir = outDir;
      this.manager = manager;
    }

    void report(String line) {
      report.append(line).append('\n');
    }

    /** Synthesizes the manager response once the request is complete. */
    private void toResponse() throws Exception {
      round++;
      byte[] request = capture.toByteArray();
      String xml = xmlPartOf(request);
      String kind = kindOf(xml);
      Files.write(Paths.get(outDir, "req" + round + "-" + kind + ".osci"), request);

      String conv = attribute(xml, "ConversationId");
      String seq = attribute(xml, "SequenceNumber");
      String reqChallenge = extract(xml, "Challenge");
      String reqResponse = extract(xml, "Response");
      String messageId = extract(xml, "MessageId");
      String chunkInfo = firstChunkInformation(xml);
      report.append("== exchange " + round + ": " + kind);
      if (!messageId.isEmpty()) {
        report.append(" MessageId=" + messageId);
      }
      report.append('\n');
      report.append("   request : conv=" + orDash(conv) + " seq=" + orDash(seq)
          + " response=" + shortB64(reqResponse) + " challenge=" + shortB64(reqChallenge) + '\n');
      if (!chunkInfo.isEmpty()) {
        report.append("   chunkInfo: " + chunkInfo + '\n');
      }

      if (conversationId == null) {
        conversationId = "1516031926756497464904932674077";
      }
      String nextChallenge = Base64.getEncoder().encodeToString(
          ("manager-challenge-" + round).getBytes(StandardCharsets.UTF_8));

      OSCIMessage rsp;
      switch (kind) {
        case "initDialog": {
          ResponseToInitDialog r = new ResponseToInitDialog(manager);
          r.setFeedback(new String[] {"0801"});
          rsp = r;
          break;
        }
        case "getMessageId": {
          ResponseToGetMessageId r = new ResponseToGetMessageId(manager);
          r.setMessageId("b3JpZ2luYWwtb3NjaWQtMQ==");
          r.setFeedback(new String[] {"0800"});
          rsp = r;
          break;
        }
        case "partialStoreDelivery": {
          ResponseToPartialStoreDelivery r = new ResponseToPartialStoreDelivery(manager);
          int chunkNumber = 1;
          if (!chunkInfo.isEmpty()) {
            int p = chunkInfo.indexOf("ChunkNumber=\"");
            if (p >= 0) {
              int s = p + "ChunkNumber=\"".length();
              chunkNumber = Integer.parseInt(chunkInfo.substring(s, chunkInfo.indexOf('"', s)));
            }
          }
          java.util.List<Integer> received = new java.util.ArrayList<>();
          for (int i = 1; i <= chunkNumber; i++) {
            received.add(i);
          }
          r.setChunkInformation(new de.osci.osci12.messageparts.ChunkInformation(
              0L, chunkNumber, received));
          r.setFeedback(new String[] {"0801"});
          rsp = r;
          break;
        }
        case "exitDialog": {
          ResponseToExitDialog r = new ResponseToExitDialog(manager);
          r.setFeedback(new String[] {"0800"});
          rsp = r;
          break;
        }
        default:
          throw new IllegalStateException("unexpected request kind: " + kind);
      }
      // pin AFTER construction: the response ctors mutate the manager
      // handler's control block themselves (Response = prevChallenge with
      // a never-populated prevChallenge, fresh Challenge)
      de.osci.osci12.soapheader.ControlBlockH cb = manager.getControlblock();
      cb.setConversationID("initDialog".equals(kind) ? conversationId : conv.isEmpty()
          ? conversationId : conv);
      cb.setResponse(reqChallenge);
      cb.setChallenge(nextChallenge);
      cb.setSequenceNumber(seq.isEmpty() || "initDialog".equals(kind) ? -1 : Integer.parseInt(seq));
      ByteArrayOutputStream ro = new ByteArrayOutputStream();
      rsp.writeXML(ro);
      response = ro.toByteArray();
      Files.write(Paths.get(outDir, "resp" + round + "-" + kind + ".osci"), response);
      String rspXml = xmlPartOf(response);
      report.append("   response: conv=" + orDash(attribute(rspXml, "ConversationId"))
          + " seq=" + orDash(attribute(rspXml, "SequenceNumber"))
          + " response=" + shortB64(reqChallenge) + " challenge=" + shortB64(nextChallenge)
          + '\n');
    }

    private static String orDash(String value) {
      return value.isEmpty() ? "-" : value;
    }

    private static String shortB64(String value) {
      if (value.isEmpty()) {
        return "-";
      }
      return value.length() <= 14 ? value : value.substring(0, 11) + "...";
    }

    /** First request-entry element name inside the XML part. */
    private static String kindOf(String xml) {
      for (String candidate : new String[] {
          "initDialog", "getMessageId", "partialStoreDelivery", "exitDialog"}) {
        // the partial kinds live in the osci2017 namespace - match any
        // prefix
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("<\\w+:" + candidate + "[\\s>/]")
            .matcher(xml);
        if (m.find()) {
          return candidate;
        }
      }
      throw new IllegalStateException("no known request entry in XML part");
    }

    /** ControlBlock child element (Response / Challenge). */
    private static String extract(String xml, String element) {
      java.util.regex.Matcher m = java.util.regex.Pattern
          .compile("<osci:" + element + ">([^<]*)</osci:" + element + ">")
          .matcher(xml);
      return m.find() ? m.group(1) : "";
    }

    /** ControlBlock attribute (ConversationId / SequenceNumber). */
    private static String attribute(String xml, String name) {
      java.util.regex.Matcher m = java.util.regex.Pattern
          .compile(name + "=\"([^\"]*)\"")
          .matcher(xml);
      return m.find() ? m.group(1) : "";
    }

    private static String firstChunkInformation(String xml) {
      java.util.regex.Matcher m = java.util.regex.Pattern
          .compile("<osci2017:ChunkInformation[^>]*>")
          .matcher(xml);
      return m.find() ? m.group() : "";
    }

    private static String xmlPartOf(byte[] stream) throws java.io.IOException {
      String head = new String(stream, StandardCharsets.UTF_8);
      String marker = "Content-ID: <osci@message>\r\n\r\n";
      int p = head.indexOf(marker);
      if (p < 0) {
        throw new IllegalStateException("no xml part");
      }
      int start = p + marker.length();
      int end = head.indexOf("\r\n--", start);
      return head.substring(start, end < 0 ? head.length() : end);
    }

    private final class CapturingStream extends ByteArrayOutputStream {
      @Override
      public void close() throws java.io.IOException {
        super.close();
        try {
          toResponse();
        } catch (Exception e) {
          throw new java.io.IOException(e);
        }
      }
    }

    @Override
    public String getVersion() {
      return "oracle-recording";
    }

    @Override
    public String getVendor() {
      return "osci-rust-rewrite";
    }

    @Override
    public de.osci.osci12.extinterfaces.TransportI newInstance() {
      return this;
    }

    @Override
    public InputStream getResponseStream() {
      return new java.io.ByteArrayInputStream(response);
    }

    @Override
    public boolean isOnline(java.net.URI uri) {
      return true;
    }

    @Override
    public long getContentLength() {
      return response.length;
    }

    @Override
    public ByteArrayOutputStream getConnection(java.net.URI uri, long length) {
      capture.reset();
      return capture;
    }
  }
}
