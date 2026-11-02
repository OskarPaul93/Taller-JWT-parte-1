package com.krakedev.jwt.services;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repository.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;

    public UsuarioService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    // Registrar usuario
//    public Usuario registrar(Usuario usuario) {
//
//        return usuarioRepository.save(usuario);
//
//    }
//
//    // Iniciar sesion
//    public Usuario login(String username, String password) {
//
//        Usuario usuario = usuarioRepository.findByUsername(username)
//                .orElse(null);
//
//        if (usuario != null && usuario.getPassword().equals(password)) {
//
//            return usuario;
//
//        }
//
//        return null;
//    }
    
    
 // Registrar usuario con contraseña protegida
    public Usuario registrar(Usuario usuario) {

        String passwordHash = BCrypt.hashpw(
                usuario.getPassword(),
                BCrypt.gensalt()
        );

        usuario.setPassword(passwordHash);

        return usuarioRepository.save(usuario);
    }

    // Iniciar sesion verificando la contraseña
    public Usuario login(String username, String password) {

        Usuario usuario = usuarioRepository.findByUsername(username)
                .orElse(null);

        if (usuario != null && BCrypt.checkpw(
                password,
                usuario.getPassword())) {

            return usuario;
        }

        return null;
    }
    
    
    
    
}
