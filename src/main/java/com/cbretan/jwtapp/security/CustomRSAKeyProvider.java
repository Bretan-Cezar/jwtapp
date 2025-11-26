package com.cbretan.jwtapp.security;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
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
public class CustomRSAKeyProvider implements RSAKeyProvider {

    @Value("${spring.security.x5u}")
    private String certURL;

    @Value("${spring.security.private-key}")
    private Resource privateKeyPath;

    private final CertificateFactory certFactory;

    private final KeyFactory keyFactory;

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {

        try (
                InputStream in = new URL(keyId).openStream();
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

    @Override
    public RSAPrivateKey getPrivateKey() {

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

    @Override
    public String getPrivateKeyId() {
        return "";
    }
}
