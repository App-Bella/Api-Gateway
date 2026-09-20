package com.ponte_bella.ms_gateway.security;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    @Value("${app.jwt.secret:pontebella-clave-secreta-compartida-con-el-gateway-cambiar-en-produccion}")
    private String secretKey;

    private SecretKey obtenerClave() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public Claims obtenerClaims(String token) {
        return Jwts.parser()
                .verifyWith(obtenerClave())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean validarToken(String token) {
        try {
            Claims claims = obtenerClaims(token);
            return claims.getExpiration() != null && !claims.getExpiration().before(new java.util.Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String obtenerUserId(String token) {
        Claims claims = obtenerClaims(token);
        return claims.getSubject();
    }

    public String obtenerEmail(String token) {
        Claims claims = obtenerClaims(token);
        return claims.get("email", String.class);
    }

    public String obtenerRol(String token) {
        Claims claims = obtenerClaims(token);
        return claims.get("rol", String.class);
    }
}
