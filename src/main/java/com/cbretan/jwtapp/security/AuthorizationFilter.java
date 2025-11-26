package com.cbretan.jwtapp.security;

import com.auth0.jwt.exceptions.JWTVerificationException;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import com.google.gson.Gson;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 *  Custom Authorization Filter.
 *  Configured as a bypass for GET requests.
 *  Checks for the presence of the Authorization header,
 *  sends 400 BAD REQUEST error response with reason if absent or empty.
 *  Performs the checks of the JWTTokenHelper.decodeAccessToken method,
 *  sends 401 UNAUTHORIZED error response with reason if one of the checks is not satisfied.
 *  Sends the request up the filter chain if all checks pass, reaching the REST controller layer.
 */
@Component
@RequiredArgsConstructor
public class AuthorizationFilter extends OncePerRequestFilter {

    private final Gson gson;

    private final JWTTokenHelper jwtTokenHelper;

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        if (request.getMethod().equals("GET")) {
            filterChain.doFilter(request, response);
            return;
        }

        var token = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (token == null || token.isEmpty()) {
            var responseBody = new AuthResponse(false, "No Authorization Header");

            statusResponse(response, HttpStatus.BAD_REQUEST, gson.toJson(responseBody));
            return;
        }

        try {
            jwtTokenHelper.decodeAccessToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        }
        catch (SecurityException | JWTVerificationException e) {

            var responseBody = new AuthResponse(false, e.getMessage());

            statusResponse(response, HttpStatus.UNAUTHORIZED, gson.toJson(responseBody));
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void statusResponse(HttpServletResponse response, HttpStatus statusCode, String body) throws IOException {
        response.setContentType("application/json");
        response.setStatus(statusCode.value());

        var out = response.getOutputStream();

        out.write(body.getBytes(StandardCharsets.UTF_8));
        out.flush();
        out.close();
    }
}
