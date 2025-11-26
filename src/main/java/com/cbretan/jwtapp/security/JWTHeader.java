package com.cbretan.jwtapp.security;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@EqualsAndHashCode
@AllArgsConstructor
public class JWTHeader {
    private final String alg;
    private final String typ;
    private final String x5u;
}
