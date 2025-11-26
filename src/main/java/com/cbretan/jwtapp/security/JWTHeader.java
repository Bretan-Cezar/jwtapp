package com.cbretan.jwtapp.security;

public record JWTHeader(String alg, String typ, String x5u) {
}
