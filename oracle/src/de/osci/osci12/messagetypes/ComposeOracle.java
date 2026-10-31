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
}
