package com.krakedev.jwt.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.services.UsuarioService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UsuarioService usuarioService;

    public AuthController(UsuarioService usuarioService) {
        this.usuarioService = usuarioService;
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

                return ResponseEntity.ok(usuarioEncontrado);

            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Usuario o contraseña incorrectos");

        } catch (Exception e) {

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al iniciar sesion: " + e.getMessage());

        }
    }
}
