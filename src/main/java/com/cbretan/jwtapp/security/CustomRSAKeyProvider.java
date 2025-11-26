package com.cbretan.jwtapp.security;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

@Component
@RequiredArgsConstructor
public class CustomRSAKeyProvider {

    @Value("${spring.security.x5u}")
    private String certURL;

    @Value("${spring.security.private-key}")
    private Resource privateKeyPath;

    private final CertificateFactory certFactory;

    private final KeyFactory keyFactory;

    /**
     * Method for fetching the certificate file from a URL and extracting the public key information.
     * @param url Provides the URL from which the public key certificate needs to be fetched.
     * @return RSA public key object
     * @throws SecurityException when the certificate URL is invalid or not accessible.
     */
    public RSAPublicKey getPublicKeyFromCertificateURL(String url) throws SecurityException {

        try (
                InputStream in = new URL(url).openStream()
        ) {
            var cert = (X509Certificate) certFactory.generateCertificate(in);

            return (RSAPublicKey) cert.getPublicKey();
        }
        catch (MalformedURLException e) {
            throw new SecurityException("Invalid certificate URL");
        }
        catch (IOException e) {
            throw new SecurityException("Could not retrieve certificate from URL");
        }
        catch (CertificateException e) {
            throw new SecurityException(e.getMessage());
        }
    }

    /**
     * Method for obtaining a private RSA key from a local file.
     * @return Private RSA key object
     * @throws SecurityException when an error occurred in reading the file or if the private key spec is invalid.
     */
    public RSAPrivateKey getPrivateKey() throws SecurityException {

        try(
                InputStream in = privateKeyPath.getInputStream();
                PemReader pemReader = new PemReader(new InputStreamReader(in))
        ) {

            var content = pemReader.readPemObject().getContent();

            var keySpec = new PKCS8EncodedKeySpec(content);

            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
        catch (IOException e) {
            throw new SecurityException(e.getMessage());
        }
        catch (InvalidKeySpecException e) {
            throw new SecurityException("Invalid private key spec");
        }
    }
}
