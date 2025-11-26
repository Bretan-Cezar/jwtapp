package com.cbretan.jwtapp.config;

import com.cbretan.jwtapp.security.JWTHeader;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

@Configuration
public class SpringApplicationConfig {

    /**
     * Certificate URL taken from YAML config.
     */
    @Value("${spring.security.x5u}")
    private String certURL;

    /**
     * Basic Gson serializer required for writing some custom response bodies for the Authorization Filter.
     * @return Gson serializer instance
     */
    @Bean
    public Gson gson() {
        return new Gson();
    }

    /**
     * Java Security RSA key factory object, used for obtaining the private key for signing JWT tokens.
     * @return RSA key factory object
     */
    @Bean
    public KeyFactory keyFactory() throws NoSuchAlgorithmException {
        return KeyFactory.getInstance("RSA");
    }

    /**
     * Java Security certificate factory object,
     * used for obtaining public keys from certificates for verifying JWT tokens.
     * @return Certificate factory object
     */
    @Bean
    public CertificateFactory certFactory() throws CertificateException {
        return CertificateFactory.getInstance("X.509");
    }

    /**
     * Valid JWT header object:
     * {
     *     "alg": "RS256",
     *     "typ": "JWT",
     *     "x5u": "..."
     * }
     */
    @Bean
    public JWTHeader validJWTHeader() {
        return new JWTHeader("RS256", "JWT", certURL);
    }
}
