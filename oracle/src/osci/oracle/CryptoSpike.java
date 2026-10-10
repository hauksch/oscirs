package osci.oracle;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Crypto spike oracle for the Rust rewrite (M0).
 *
 * Reproduces the exact JCA parameterization of the OSCI 1.2 library defaults:
 *  - signatures: RSA-PSS via BouncyCastle's "SHA256withRSAandMGF1"
 *    (MGF1-SHA256, salt length = digest length), signing raw payload bytes
 *  - key transport: "RSA/ECB/OAEPPadding" with
 *    OAEPParameterSpec(SHA-256, MGF1, MGF1-SHA256, empty PSource)
 *
 * Modes (line-based key=value protocol on stdout/stdin, base64 payloads):
 *  vectors            emit spike vectors produced with the corpus test keys
 *  verify    (stdin)  payload_b64 + signature_b64 -> VERIFY_OK | VERIFY_FAIL
 *  unwrap    (stdin)  wrapped_key_b64 -> UNWRAP_OK <key_b64> | UNWRAP_FAIL
 *
 * The keystores live in the extracted test corpus (see scripts/extract-testcorpus.sh);
 * every keystore has the password 123456.
 */
public final class CryptoSpike {

  private static final String KEYSTORE_PASSWORD = "123456";
  private static final String PSS_JCA = "SHA256withRSAandMGF1";
  private static final byte[] PAYLOAD = "osci-rust-rewrite crypto spike payload 0123456789".getBytes(StandardCharsets.UTF_8);

  public static void main(String[] args) throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    String corpus = System.getenv("OSCI_CORPUS");
    if (corpus == null) {
      Path cwd = Paths.get("").toAbsolutePath();
      corpus = cwd.resolve("testcorpus").toString();
      if (!Files.exists(Path.of(corpus, "certs"))) {
        corpus = cwd.resolveSibling("testcorpus").toString();
      }
    }
    String mode = args.length > 0 ? args[0] : "vectors";
    switch (mode) {
      case "vectors":
        cmdVectors(corpus);
        break;
      case "verify":
        cmdVerify(corpus);
        break;
      case "unwrap":
        cmdUnwrap(corpus);
        break;
      default:
        System.err.println("usage: CryptoSpike vectors|verify|unwrap");
        System.exit(2);
    }
  }

  private static void cmdVectors(String corpus) throws Exception {
    KeyStore.Entry secret = loadEntry(corpus, "certs/alice_signature_4096.p12");
    PrivateKey sigKey = ((KeyStore.PrivateKeyEntry) secret).getPrivateKey();
    X509Certificate sigCert = (X509Certificate) ((KeyStore.PrivateKeyEntry) secret).getCertificate();

    Signature engine = Signature.getInstance(PSS_JCA);
    engine.initSign(sigKey, new SecureRandom());
    engine.update(PAYLOAD);
    byte[] signature = engine.sign();

    KeyStore.Entry cipherEntry = loadEntry(corpus, "certs/alice_cipher_4096.p12");
    PrivateKey cipherKey = ((KeyStore.PrivateKeyEntry) cipherEntry).getPrivateKey();
    X509Certificate cipherCert = (X509Certificate) ((KeyStore.PrivateKeyEntry) cipherEntry).getCertificate();

    KeyGenerator kg = KeyGenerator.getInstance("AES");
    kg.init(256);
    SecretKey sessionKey = kg.generateKey();

    Cipher wrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
    wrap.init(Cipher.WRAP_MODE, cipherCert.getPublicKey(),
              new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    byte[] wrapped = wrap.wrap(sessionKey);

    Base64.Encoder b64 = Base64.getEncoder();
    System.out.println("payload_b64=" + b64.encodeToString(PAYLOAD));
    System.out.println("pss_signature_b64=" + b64.encodeToString(signature));
    System.out.println("signature_cert_der_b64=" + b64.encodeToString(sigCert.getEncoded()));
    System.out.println("session_key_b64=" + b64.encodeToString(sessionKey.getEncoded()));
    System.out.println("wrapped_key_b64=" + b64.encodeToString(wrapped));
  }

  private static void cmdVerify(String corpus) throws Exception {
    java.util.Map<String, byte[]> in = readStdin();
    KeyStore.Entry entry = loadEntry(corpus, "certs/alice_signature_4096.p12");
    X509Certificate cert = (X509Certificate) ((KeyStore.PrivateKeyEntry) entry).getCertificate();

    Signature engine = Signature.getInstance(PSS_JCA);
    engine.initVerify(cert.getPublicKey());
    engine.update(in.get("payload_b64"));
    System.out.println(engine.verify(in.get("signature_b64")) ? "VERIFY_OK" : "VERIFY_FAIL");
  }

  private static void cmdUnwrap(String corpus) throws Exception {
    java.util.Map<String, byte[]> in = readStdin();
    KeyStore.Entry entry = loadEntry(corpus, "certs/alice_cipher_4096.p12");
    PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();

    Cipher unwrap = Cipher.getInstance("RSA/ECB/OAEPPadding");
    unwrap.init(Cipher.DECRYPT_MODE, key,
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    byte[] recovered = unwrap.doFinal(in.get("wrapped_key_b64"));
    System.out.println("UNWRAP_OK " + Base64.getEncoder().encodeToString(recovered));
  }

  private static KeyStore.Entry loadEntry(String corpus, String name) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (var in = Files.newInputStream(Path.of(corpus, name))) {
      ks.load(in, KEYSTORE_PASSWORD.toCharArray());
    }
    String alias = null;
    for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
      alias = e.nextElement();
      if (ks.isKeyEntry(alias)) {
        break;
      }
    }
    return ks.getEntry(alias, new KeyStore.PasswordProtection(KEYSTORE_PASSWORD.toCharArray()));
  }

  private static java.util.Map<String, byte[]> readStdin() throws Exception {
    byte[] all = System.in.readAllBytes();
    java.util.Map<String, byte[]> out = new java.util.HashMap<>();
    for (String line : new String(all, StandardCharsets.UTF_8).split("\\R")) {
      int eq = line.indexOf('=');
      if (eq > 0) {
        out.put(line.substring(0, eq), Base64.getDecoder().decode(line.substring(eq + 1)));
      }
    }
    return out;
  }

  private CryptoSpike() {
  }
}
