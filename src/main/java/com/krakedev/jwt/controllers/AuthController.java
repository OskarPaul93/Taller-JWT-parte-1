package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final JwtUtil jwtUtil;

    public AuthController(UsuarioService usuarioService, JwtUtil jwtUtil) {
        this.usuarioService = usuarioService;
        this.jwtUtil = jwtUtil;
    }

    // Registrar usuario
    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {

        try {

            Usuario nuevoUsuario = usuarioService.registrar(usuario);

            return new ResponseEntity<>(nuevoUsuario, HttpStatus.CREATED);

        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario: " + e.getMessage());

        }
    }

    // Iniciar sesion
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Usuario usuario) {

        try {

            Usuario usuarioEncontrado = usuarioService.login(
                    usuario.getUsername(),
                    usuario.getPassword()
            );

            if (usuarioEncontrado != null) {

            	String token = jwtUtil.generarToken(
                        usuarioEncontrado.getUsername(),
                        usuarioEncontrado.getRol()
                );
            	
            	
            	//return ResponseEntity.ok(usuarioEncontrado);
            	 return ResponseEntity.ok(
                         Map.of(
                                 "mensaje", "Inicio de sesión correcto",
                                 "token", token,
                                 "tipo", "Bearer",
                                 "id", usuarioEncontrado.getId(),
                                 "username", usuarioEncontrado.getUsername(),
                                 "rol", usuarioEncontrado.getRol()
                         )
                 );

            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o contraseña incorrectos");

        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al iniciar sesion: " + e.getMessage());

        }
    }
    @GetMapping("/perfil")
    public ResponseEntity<?> perfil(@RequestHeader(value = "Authorization", required = false) String authorization) {

        try {
            // Verificar que exista la cabecera Bearer
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body("Token no proporcionado");
            }

            // Extraer el token de la cabecera
            String token = authorization.substring(7);

            // Validar la firma y la expiración
            com.auth0.jwt.interfaces.DecodedJWT jwt =
                    jwtUtil.verificarToken(token);

            // Obtener los datos del usuario desde el token validado
            String username = jwt.getSubject();
            String rol = jwt.getClaim("rol").asString();

            // Saludo según el rol
            String mensaje;

            if ("ADMIN".equals(rol)) {
                mensaje = "Bienvenido voluntario " + username
                        + ". Tienes acceso como administrador.";
            } else if ("USER".equals(rol)) {
                mensaje = "Bienvenido adoptante " + username
                        + ". Puedes consultar tu perfil.";
            } else {
                mensaje = "Bienvenido " + username;
            }

            return ResponseEntity.ok(
                    java.util.Map.of(
                            "username", username,
                            "rol", rol,
                            "mensaje", mensaje
                    )
            );
        } catch (com.auth0.jwt.exceptions.JWTVerificationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Token inválido o expirado");
        }
    }
    
  
}
