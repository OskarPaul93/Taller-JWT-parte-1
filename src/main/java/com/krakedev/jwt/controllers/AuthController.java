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
}
