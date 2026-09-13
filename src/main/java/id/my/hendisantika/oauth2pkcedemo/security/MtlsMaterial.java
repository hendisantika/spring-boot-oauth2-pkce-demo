package id.my.hendisantika.oauth2pkcedemo.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Created by IntelliJ IDEA.
 * Project : spring-boot-oauth2-pkce-demo
 * User: hendisantika
 * Email: hendisantika@gmail.com
 * Telegram : @hendisantika34
 * Date: 13/09/26
 * Time: 15.02
 */
@Slf4j
@Getter
public final class MtlsMaterial {

    public static final char[] PASSWORD = "changeit".toCharArray();

    private final X509Certificate serverCertificate;
    private final X509Certificate clientCertificate;
    private final PrivateKey clientPrivateKey;

    /**
     * A second client certificate, trusted by the transport and registered to nobody. It exists so
     * that a refusal can come from the authorization server rather than from the TLS handshake -
     * a connection that is never established demonstrates nothing about what the server checks.
     */
    private final X509Certificate strangerCertificate;

    /** Written to temp files because Tomcat's SSL configuration takes keystore paths. */
    private final Path serverKeyStorePath;
    private final Path clientKeyStorePath;
    private final Path strangerKeyStorePath;
    private final Path trustStorePath;

    private MtlsMaterial(X509Certificate serverCertificate, PrivateKey serverKey,
                         X509Certificate clientCertificate, PrivateKey clientKey,
                         X509Certificate strangerCertificate, PrivateKey strangerKey) throws Exception {
        this.serverCertificate = serverCertificate;
        this.clientCertificate = clientCertificate;
        this.clientPrivateKey = clientKey;
        this.strangerCertificate = strangerCertificate;

        this.serverKeyStorePath = writeKeyStore("mtls-server", "server", serverKey, serverCertificate);
        this.clientKeyStorePath = writeKeyStore("mtls-client", "client", clientKey, clientCertificate);
        this.strangerKeyStorePath =
                writeKeyStore("mtls-stranger", "stranger", strangerKey, strangerCertificate);
        // Tomcat needs to trust a client certificate before it will accept it on the handshake, and
        // the demo client needs to trust the server's. One store does for all of them here - the
        // stranger included, so that its requests reach the server and are turned away by it.
        this.trustStorePath = writeTrustStore(serverCertificate, clientCertificate, strangerCertificate);
    }

    public static MtlsMaterial generate() {
        try {
            KeyPair serverKeys = rsaKeyPair();
            KeyPair clientKeys = rsaKeyPair();
            KeyPair strangerKeys = rsaKeyPair();
            X509Certificate server = selfSigned("CN=localhost", serverKeys, true);
            X509Certificate client = selfSigned("CN=pkce-mtls-client", clientKeys, false);
            X509Certificate stranger = selfSigned("CN=somebody-else", strangerKeys, false);
            log.info("Generated self-signed mTLS material, client thumbprint {}",
                    thumbprintOf(client));
            return new MtlsMaterial(server, serverKeys.getPrivate(), client, clientKeys.getPrivate(),
                    stranger, strangerKeys.getPrivate());
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate the mTLS demo certificates", ex);
        }
    }

    /**
     * RFC 8705 section 3.1: a certificate-bound token carries {@code cnf.x5t#S256}, the base64url
     * SHA-256 of the DER-encoded certificate. This computes the same value so the page can show the
     * two matching.
     */
    public String strangerCertificateThumbprint() {
        return thumbprintOf(strangerCertificate);
    }

    public Path getStrangerKeyStorePath() {
        return strangerKeyStorePath;
    }

    public String clientCertificateThumbprint() {
        return thumbprintOf(clientCertificate);
    }

    /**
     * The client's public key published with its certificate chain. Spring Authorization Server
     * verifies a self-signed client certificate by fetching this and looking for a key whose x5c
     * matches what was presented on the TLS handshake, so the x5c is what makes it work.
     */
    public String clientJwkSetJson() {
        try {
            RSAKey jwk = new RSAKey.Builder((RSAPublicKey) clientCertificate.getPublicKey())
                    .keyID(clientCertificate.getSerialNumber().toString())
                    .x509CertChain(List.of(Base64.encode(clientCertificate.getEncoded())))
                    .build();
            return new JWKSet(jwk).toString();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to publish the client certificate as a JWK", ex);
        }
    }

    public String clientSubjectDn() {
        return clientCertificate.getSubjectX500Principal().getName();
    }

    private static String thumbprintOf(X509Certificate certificate) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute the certificate thumbprint", ex);
        }
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSigned(String subject, KeyPair keyPair, boolean serverAuth)
            throws Exception {
        Instant now = Instant.now();
        X500Name name = new X500Name(subject);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(Duration.ofDays(1))),
                // Issuer equals subject: self-signed, which is what
                // self_signed_tls_client_auth expects.
                name,
                keyPair.getPublic());
        if (serverAuth) {
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        }
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate())));
    }

    private static Path writeKeyStore(String fileName, String alias, PrivateKey key,
                                      X509Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, key, PASSWORD, new java.security.cert.Certificate[]{certificate});
        return write(fileName, keyStore);
    }

    private static Path writeTrustStore(X509Certificate... certificates) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        for (int i = 0; i < certificates.length; i++) {
            trustStore.setCertificateEntry("trusted-" + i, certificates[i]);
        }
        return write("mtls-trust", trustStore);
    }

    private static Path write(String fileName, KeyStore keyStore) throws Exception {
        Path path = Files.createTempFile(fileName, ".p12");
        path.toFile().deleteOnExit();
        try (OutputStream out = Files.newOutputStream(path)) {
            keyStore.store(out, PASSWORD);
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to write " + path, ex);
        }
        return path;
    }
}
