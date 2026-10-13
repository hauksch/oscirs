package osci.oracle;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.Reader;
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
      case "canonize":
        cmdCanonize();
        break;
      case "validate":
        cmdValidate(args.length > 1 ? args[1] : "../testcorpus/xsd");
        break;
      case "loadverify":
        cmdLoadVerify(corpus);
        break;
      default:
        System.err.println("usage: CryptoSpike vectors|verify|unwrap|canonize|validate [xsddir]|loadverify");
        System.exit(2);
    }
  }

  /**
   * Validate the XML from stdin against the XSD corpus. The schemas to
   * load are taken from the document's xsi:schemaLocation hints plus the
   * extern set (soap envelope, xmldsig, xmlenc), mirroring the reference
   * SchemaValidation test.
   */
  private static void cmdValidate(String xsdDir) throws Exception {
    byte[] xml = System.in.readAllBytes();
    javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    // The XML comes from fixture corpora that fuzzing and differential
    // testing mutate - harden against XXE (the Rust parser under test is
    // XXE-safe; the oracle must not be the soft target).
    dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    org.w3c.dom.Document doc = dbf.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml));
    StringBuilder hints = new StringBuilder();
    org.w3c.dom.NamedNodeMap attrs = doc.getDocumentElement().getAttributes();
    for ( int i = 0 ; i < attrs.getLength() ; i++ )
    {
      org.w3c.dom.Node a = attrs.item(i);
      if (a.getNodeName().endsWith("schemaLocation"))
        hints.append(' ').append(a.getNodeValue());
    }
    java.io.File dir = new java.io.File(xsdDir);
    java.io.File extern = new java.io.File(dir, "extern");
    String[] tokens = hints.toString().trim().split("\\s+");
    if (tokens.length < 2)
    {
      System.err.println("NO_SCHEMA_HINT");
      System.exit(4);
    }
    java.io.File root = new java.io.File(dir, tokens[1]);
    if (!root.exists())
    {
      System.err.println("SCHEMA_MISSING " + tokens[1]);
      System.exit(4);
    }
    javax.xml.validation.SchemaFactory sf =
        javax.xml.validation.SchemaFactory.newInstance(javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
    sf.setFeature("http://apache.org/xml/features/validation/schema-full-checking", false);
    sf.setResourceResolver(new org.w3c.dom.ls.LSResourceResolver()
    {
      @Override
      public org.w3c.dom.ls.LSInput resolveResource(String type, String namespaceURI,
                                                    String publicId, String systemId, String baseURI)
      {
        if (systemId == null)
          return null;
        // catalog.xml maps well-known namespace URIs to corpus files
        String name = systemId.replaceAll(".*[/\\\\]", "");
        if (systemId.equals("http://schemas.xmlsoap.org/soap/envelope/"))
          name = "soap-envelope.xsd";
        else if (systemId.equals("http://www.w3.org/2000/09/xmldsig#"))
          name = "xmldsig-core-schema.xsd";
        else if (systemId.equals("http://www.w3.org/2001/04/xmlenc#"))
          name = "xenc-schema.xsd";
        else if (systemId.equals("http://www.w3.org/2009/xmlenc11#"))
          name = "xenc-schema-11.xsd";
        else if (systemId.equals("http://www.w3.org/XML/1998/namespace"))
          name = "xml.xsd";
        for (java.io.File d : new java.io.File[] {dir, extern})
        {
          java.io.File f = new java.io.File(d, name);
          if (f.exists())
          {
            try
            {
              final java.io.InputStream in = new java.io.FileInputStream(f);
              return new org.w3c.dom.ls.LSInput()
              {
                @Override public Reader getCharacterStream() { return null; }
                @Override public void setCharacterStream(Reader r) { }
                @Override public InputStream getByteStream() { return in; }
                @Override public void setByteStream(InputStream b) { }
                @Override public String getStringData() { return null; }
                @Override public void setStringData(String s) { }
                @Override public String getSystemId() { return f.toURI().toString(); }
                @Override public void setSystemId(String s) { }
                @Override public String getPublicId() { return null; }
                @Override public void setPublicId(String s) { }
                @Override public String getBaseURI() { return null; }
                @Override public void setBaseURI(String s) { }
                @Override public String getEncoding() { return null; }
                @Override public void setEncoding(String s) { }
                @Override public boolean getCertifiedText() { return false; }
                @Override public void setCertifiedText(boolean c) { }
              };
            }
            catch (java.io.FileNotFoundException e)
            {
              return null;
            }
          }
        }
        return null;
      }
    });
    javax.xml.validation.Schema schema =
        sf.newSchema(new javax.xml.transform.stream.StreamSource(root));
    javax.xml.validation.Validator validator = schema.newValidator();
    try
    {
      validator.validate(new javax.xml.transform.stream.StreamSource(new ByteArrayInputStream(xml)));
      System.out.println("VALID");
    }
    catch (org.xml.sax.SAXParseException e)
    {
      System.out.println("INVALID line " + e.getLineNumber() + " col " + e.getColumnNumber() + ": " + e.getMessage());
      System.exit(5);
    }
  }

  /**
   * Load a full MIME message from stdin through the reference library's
   * own parser (StoredMessage.loadMessage): structural parse plus
   * transport-signature verification. Success means the reference
   * implementation accepts the message.
   */
  private static void cmdLoadVerify(String corpus) throws Exception {
    byte[] message = System.in.readAllBytes();
    try
    {
      de.osci.osci12.messagetypes.StoredMessage sm =
          de.osci.osci12.messagetypes.StoredMessage.loadMessageCheckingSignature(
              new ByteArrayInputStream(message));
      System.out.println("LOADED type=" + sm.getClass().getSimpleName()
                         + " signed=" + sm.isSigned());
    }
    catch (Throwable t)
    {
      Throwable root = t;
      while (root.getCause() != null)
        root = root.getCause();
      System.out.println("REJECTED " + root);
      System.exit(6);
    }
  }

  /**
   * Canonicalize the XML from stdin with the reference Canonizer and print
   * the canonical bytes plus the digest map, all base64-encoded, for
   * differential testing against the Rust canonicalizer:
   *   CANON_B64 <base64 of the canonical document>
   *   DIGEST <#id> <base64 digest>
   *   SIGNEDINFO <base64 | ->   (per entry, '-' for the null placeholder)
   */
  private static void cmdCanonize() throws Exception {
    byte[] xml = System.in.readAllBytes();
    de.osci.helper.Canonizer can = new de.osci.helper.Canonizer(new ByteArrayInputStream(xml), null);
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    can.transferTo(bos);
    // NB: Canonizer stores e.getException(), which is null when the
    // SAXException itself is the parse error - guard against silently
    // empty output as well.
    if (can.getCanException() != null || (bos.size() == 0 && xml.length > 0))
    {
      System.err.println("CANON_FAILED: " + can.getCanException());
      System.exit(3);
    }
    Base64.Encoder b64 = Base64.getEncoder();
    System.out.println("CANON_B64 " + b64.encodeToString(bos.toByteArray()));
    can.getDigestValues().forEach((id, digest) -> System.out.println("DIGEST " + id + " " + b64.encodeToString(digest)));
    can.getSignedInfos().forEach(si -> System.out.println("SIGNEDINFO " + (si == null ? "-" : b64.encodeToString(si))));
    for (String prop : can.getSignedProperties())
      System.out.println("SIGNEDPROP " + b64.encodeToString(prop.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    for (String ns : can.getContainerNS())
      System.out.println("COCONS " + b64.encodeToString(ns.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
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
