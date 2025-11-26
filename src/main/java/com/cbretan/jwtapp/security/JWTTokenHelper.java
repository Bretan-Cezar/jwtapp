package com.cbretan.jwtapp.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.google.gson.Gson;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class JWTTokenHelper {

    @Autowired
    private Environment env;

    /**
     * JWT token validity period in seconds.
     */
    private Long jwtExpirationTime;

    /**
     * RSA keys provider for the RS256 signature verification and signing algorithm.
     */
    private final CustomRSAKeyProvider keyProvider;

    private final JWTHeader validJWTHeader;

    private final Gson gson;

    @PostConstruct
    private void init() {
        jwtExpirationTime = Long.valueOf(Objects.requireNonNull(env.getProperty("spring.security.jwt-exp")));
    }

    /**
     * Method for verifying a JWT token's integrity and authenticity.
     * Uses the RS256 algorithm with a provided public key.
     * @param header Raw Authorization header from the request.
     * @throws SecurityException when:
     *  - the first 7 characters of the header aren't "Bearer "
     *  - the JWT headers don't match the values considered as valid
     *  - the JWT token is in an invalid format
     *  - the certificate URL is invalid or not accessible
     *  - the interval between the iat and exp claims is different from the jwtExpiration time
     *  - the token's expired
     * @throws JWTVerificationException when:
     *  - the token's signature is invalid
     */
    public void decodeAccessToken(String header) throws SecurityException, JWTVerificationException {
        if (!header.startsWith("Bearer ")) {
            throw new SecurityException("Access token header does not start with `Bearer `");
        }

        var token = header.substring(7);

        var decodedJWT = JWT.decode(token);

        var jwtHeader = new JWTHeader(
                decodedJWT.getHeaderClaim("alg").asString(),
                decodedJWT.getHeaderClaim("typ").asString(),
                decodedJWT.getHeaderClaim("x5u").asString()
        );

        if (!jwtHeader.equals(validJWTHeader)) {
            throw new SecurityException("Invalid JWT token header");
        }

        var jwtVerifier = JWT.require(
                Algorithm.RSA256(
                        keyProvider.getPublicKeyFromCertificateURL(jwtHeader.x5u()),
                        keyProvider.getPrivateKey()
                )
        ).build();

        decodedJWT = jwtVerifier.verify(token);

        var issueDate = decodedJWT.getIssuedAt();
        var actualExpDate = new Date(issueDate.getTime() + jwtExpirationTime * 1000);
        var expDate = decodedJWT.getExpiresAt();
        var currentDate = new Date();

        if (!expDate.equals(actualExpDate)) {
            throw new SecurityException("Expiration date mismatch");
        }

        if (currentDate.after(expDate)) {
            throw new SecurityException("JWT token expired");
        }
    }

    /**
     * Method for creating a new valid JWT token, signed by the RS256 algorithm with a provided private key.
     * @return A new valid JWT token.
     */
    public String createAccessToken() {

        var headerClaims = new HashMap<String, Object>();

        headerClaims.put("alg", validJWTHeader.alg());
        headerClaims.put("typ", validJWTHeader.typ());
        headerClaims.put("x5u", validJWTHeader.x5u());

        var currentDate = new Date();
        var expDate = new Date(currentDate.getTime() + jwtExpirationTime * 1000);

        return JWT.create()
                .withHeader(headerClaims)
                .withIssuedAt(currentDate)
                .withExpiresAt(expDate)
                .withSubject("test")
                .sign(Algorithm.RSA256(
                        keyProvider.getPublicKeyFromCertificateURL(validJWTHeader.x5u()),
                        keyProvider.getPrivateKey())
                );
    }
}
