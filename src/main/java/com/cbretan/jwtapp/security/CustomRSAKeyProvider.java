package com.cbretan.jwtapp.security;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.util.encoders.Base64;

@Component
@RequiredArgsConstructor
public class CustomRSAKeyProvider {

    @Value("${spring.security.x5u}")
    private String certURL;

    @Value("${spring.security.private-key}")
    private Resource privateKeyPath;

    @Value("${spring.security.passphrase}")
    private String encPassphrase;

    private final BouncyCastleProvider bouncyCastleProvider;

    private final CertificateFactory certFactory;

    private final KeyFactory keyFactory;

    private JcaPEMKeyConverter pkConverter;

    @PostConstruct
    private void init() {
        pkConverter = new JcaPEMKeyConverter().setProvider(bouncyCastleProvider);
    }

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
     * Method for obtaining a private RSA key from a local encrypted PEM.
     * The passphrase is obtained from the configuration file, and must be encoded in Base64.
     * @return Private RSA key object
     * @throws SecurityException when an error occurred in reading the file or if the private key spec is invalid.
     */
    public RSAPrivateKey getPrivateKey() throws SecurityException {

        try(
                InputStream in = privateKeyPath.getInputStream();
                PEMParser pemParser = new PEMParser(new InputStreamReader(in))
        ) {

            var parsedObject = pemParser.readObject();

            if (parsedObject instanceof PKCS8EncryptedPrivateKeyInfo encKey) {

                var builder = new JcePKCSPBEInputDecryptorProviderBuilder().setProvider(bouncyCastleProvider);

                var passphrase = new String(Base64.decode(encPassphrase), StandardCharsets.UTF_8).strip();
                var inputDecryptorProvider = builder.build(passphrase.toCharArray());

                var pkInfo = encKey.decryptPrivateKeyInfo(inputDecryptorProvider);

                return (RSAPrivateKey) pkConverter.getPrivateKey(pkInfo);
            }
            else {
                throw new SecurityException("Invalid private key spec");
            }

        }
        catch (IOException e) {
            throw new SecurityException(e.getMessage());
        }
        catch (PKCSException e) {
            throw new SecurityException("Invalid private key spec");
        }
    }
}
