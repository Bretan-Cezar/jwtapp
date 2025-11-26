package com.cbretan.jwtapp.web;

import com.cbretan.jwtapp.security.AuthResponse;
import com.cbretan.jwtapp.security.JWTTokenHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AppRestController {

    private final JWTTokenHelper jwtTokenHelper;

    /**
     * POST endpoint meant to be accessible only with a valid JWT token.
     * @return HTTP OK Response with a body indicating a valid header.
     */
    @PostMapping("/")
    public ResponseEntity<AuthResponse> dummyEndpoint() {

        return ResponseEntity.ok(new AuthResponse(true, ""));
    }

    /**
     * GET endpoint meant for obtaining a valid JWT token.
     * @return HTTP OK Response with a body containing a valid JWT token.
     */
    @GetMapping("/")
    public ResponseEntity<AuthResponse> jwtEndpoint() {

        return ResponseEntity.ok(new AuthResponse(true, jwtTokenHelper.createAccessToken()));
    }
}
