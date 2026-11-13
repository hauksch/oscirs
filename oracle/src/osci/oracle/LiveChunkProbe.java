package osci.oracle;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Live EFFI probe: drives the reference 2.6.1 client's chunked exchange
 * (Init -> GetMessageId -> PartialStoreDelivery x N -> ExitDialog, the
 * ComposeOracle.chunkedExchange flow) against a REAL intermediary, for
 * wire-level comparison with a Rust client's attempts. Every request and
 * response is captured to the output directory.
 */
public final class LiveChunkProbe {

  private static final String KEYSTORE_PASSWORD = "123456";

  private LiveChunkProbe() {
  }

  /** Buffering transport that POSTs each completed request live. */
  private static final class HttpTransport
      implements de.osci.osci12.extinterfaces.TransportI {
    private final String outDir;
    private final URI endpoint;
    private final ByteArrayOutputStream capture = new ByteArrayOutputStream() {
      @Override
      public void close() throws java.io.IOException {
        super.close();
        try {
          send();
        } catch (java.io.IOException e) {
          throw e;
        } catch (Exception e) {
          throw new java.io.IOException(e);
        }
      }
    };
    private byte[] response = new byte[0];
    private int round = 0;

    HttpTransport(String outDir, URI endpoint) {
      this.outDir = outDir;
      this.endpoint = endpoint;
    }

    private void send() throws Exception {
      round++;
      byte[] request = capture.toByteArray();
      Files.write(Paths.get(outDir, "req" + round + ".osci"), request);
      HttpURLConnection http = (HttpURLConnection) endpoint.toURL().openConnection();
      http.setInstanceFollowRedirects(false);
      http.setRequestMethod("POST");
      http.setRequestProperty("Content-Type", "text/xml");
      http.setRequestProperty("charset", "utf-8");
      http.setFixedLengthStreamingMode(request.length);
      http.setConnectTimeout(30_000);
      http.setReadTimeout(300_000);
      http.setUseCaches(false);
      http.setDoOutput(true);
      try (OutputStream out = http.getOutputStream()) {
        out.write(request);
      }
      int code = http.getResponseCode();
      try (InputStream in = code >= 400 ? http.getErrorStream() : http.getInputStream()) {
        response = in.readAllBytes();
      }
      Files.write(Paths.get(outDir, "resp" + round + ".osci"), response);
      System.err.println("round " + round + ": HTTP " + code + ", request "
          + request.length + " B, response " + response.length + " B");
    }

    @Override
    public String getVersion() {
      return "live-probe";
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
    public boolean isOnline(URI uri) {
      return true;
    }

    @Override
    public long getContentLength() {
      return response.length;
    }

    @Override
    public ByteArrayOutputStream getConnection(URI uri, long length) {
      capture.reset();
      return capture;
    }
  }

  /** Transport placeholder for the throwaway full-delivery compose —
   * never used (nothing is transmitted). */
  private static final class NullTransport
      implements de.osci.osci12.extinterfaces.TransportI {
    @Override
    public String getVersion() {
      return "probe-null";
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
    public boolean isOnline(URI uri) {
      return false;
    }

    @Override
    public long getContentLength() {
      return -1;
    }

    @Override
    public ByteArrayOutputStream getConnection(URI uri, long length) {
      throw new IllegalStateException("no transmission over the null transport");
    }
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      System.err.println("usage: LiveChunkProbe <endpoint-url> <corpus-dir> <out-dir>");
      System.exit(2);
    }
    URI endpoint = new URI(args[0]);
    String corpus = args[1];
    String outDir = args[2];
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
        null, intermedCipherCert, endpoint);
    de.osci.osci12.roles.Addressee addressee =
        new de.osci.osci12.roles.Addressee(null, bobCipherCert);

    HttpTransport transport = new HttpTransport(outDir, endpoint);
    de.osci.osci12.common.DialogHandler dialog = new de.osci.osci12.common.DialogHandler(
        originator, intermed, transport);
    dialog.setLanguageList("de");
    dialog.setCreateSignatures(true);
    dialog.setEncryption(false);

    new de.osci.osci12.messagetypes.InitDialog(dialog).send();
    de.osci.osci12.messagetypes.ResponseToGetMessageId rsp =
        new de.osci.osci12.messagetypes.GetMessageId(dialog).send();
    String oscid = rsp.getMessageId();

    // the full delivery on a THROWAWAY dialog - same as the oracle
    de.osci.osci12.common.DialogHandler strDel = new de.osci.osci12.common.DialogHandler(
        originator, intermed, new NullTransport());
    strDel.setCreateSignatures(true);
    de.osci.osci12.messagetypes.StoreDelivery full =
        new de.osci.osci12.messagetypes.StoreDelivery(strDel, addressee, oscid);
    full.setSubject("S");
    de.osci.osci12.messageparts.ContentContainer coco =
        new de.osci.osci12.messageparts.ContentContainer();
    byte[] blob = new byte[2_500_000];
    Arrays.fill(blob, (byte) 'A');
    de.osci.osci12.messageparts.Attachment fullAtt =
        new de.osci.osci12.messageparts.Attachment(
            new java.io.ByteArrayInputStream(blob), "FullBlob");
    coco.addContent(new de.osci.osci12.messageparts.Content(fullAtt));
    full.addContentContainer(coco);
    ByteArrayOutputStream fullOut = new ByteArrayOutputStream();
    full.writeMessage(fullOut);
    byte[] fullBytes = fullOut.toByteArray();

    long chunkSizeKB = 1000;
    long chunkSizeBytes = chunkSizeKB * 1024;
    int totalChunks = (int) ((fullBytes.length + chunkSizeBytes - 1) / chunkSizeBytes);
    long totalKB = fullBytes.length / 1024;
    System.err.println("full delivery " + fullBytes.length + " B -> "
        + totalChunks + " chunks, TotalMessageSize=" + totalKB + " KB");

    for (int i = 1; i <= totalChunks; i++) {
      int from = (int) ((i - 1) * chunkSizeBytes);
      int to = (int) Math.min(fullBytes.length, i * chunkSizeBytes);
      byte[] chunk = Arrays.copyOfRange(fullBytes, from, to);
      de.osci.osci12.messageparts.ChunkInformation ci =
          new de.osci.osci12.messageparts.ChunkInformation(chunkSizeKB, i, totalKB, totalChunks);
      de.osci.osci12.messagetypes.PartialStoreDelivery partial =
          new de.osci.osci12.messagetypes.PartialStoreDelivery(dialog, addressee, ci, oscid);
      partial.setChunkBlob(new java.io.ByteArrayInputStream(chunk));
      de.osci.osci12.messagetypes.ResponseToPartialStoreDelivery r = partial.send();
      String[][] fb = r.getFeedback();
      System.err.println("chunk " + i + ": feedback="
          + (fb.length > 0 ? fb[0][0] + " " + fb[0][1] : "none"));
    }
    new de.osci.osci12.messagetypes.ExitDialog(dialog).send();
    System.err.println("exchange complete");
  }
}
