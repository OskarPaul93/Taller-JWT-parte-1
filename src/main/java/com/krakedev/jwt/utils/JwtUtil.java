package com.krakedev.jwt.utils;

import java.util.Date;

import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

@Component
public class JwtUtil {

    // Clave secreta para firmar los tokens
    private static final String SECRET_KEY = "PatitasAlRescate_ClaveSecreta_2026";

    // Tiempo de validez: 30 minutos expresado en segundos
    private static final long EXPIRATION_TIME = 1800000;

    // Generar token JWT
    public String generarToken(String username, String rol) {

        Algorithm algoritmo = Algorithm.HMAC256(SECRET_KEY);

        return JWT.create()
                .withSubject(username)
                .withClaim("rol", rol)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(algoritmo);
    }

    // Verificar y decodificar token
    public DecodedJWT verificarToken(String token) {

        Algorithm algoritmo = Algorithm.HMAC256(SECRET_KEY);

        return JWT.require(algoritmo)
                .build()
                .verify(token);
    }
}

