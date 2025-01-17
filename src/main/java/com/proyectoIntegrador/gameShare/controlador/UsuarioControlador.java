package com.proyectoIntegrador.gameShare.controlador;

import com.proyectoIntegrador.gameShare.dto.UsuarioRegistroDTO;
import com.proyectoIntegrador.gameShare.entidad.Usuario;
import com.proyectoIntegrador.gameShare.servicio.UsuarioServicio;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/usuarios")
@AllArgsConstructor
//@CrossOrigin(origins = "http://localhost:5173")
//@CrossOrigin("*")
@CrossOrigin(origins = {"https://frontendgameshare.up.railway.app","http://localhost:5173"})
public class UsuarioControlador {
    private final UsuarioServicio usuarioServicio;

    @PostMapping("/nuevo")
    public ResponseEntity<Usuario> registrarUsuario(@Valid @RequestBody UsuarioRegistroDTO usuarioDTO) {
        Optional<Usuario> usuarioBuscado = usuarioServicio.buscarUsuarioPorEmail(usuarioDTO.getEmail());

        if (usuarioBuscado.isPresent()) {
            return ResponseEntity.status(409).build();  // 409 Conflict si el usuario ya existe
        } else {
            return ResponseEntity.ok(usuarioServicio.registrarUsuario(usuarioDTO));
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<Usuario> buscarUsuarioPorID(@PathVariable Long id) {
        Optional<Usuario> usuarioBuscado = usuarioServicio.buscarUsuarioPorID(id);
        if (usuarioBuscado.isPresent())
            return ResponseEntity.ok(usuarioBuscado.get());
        else {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping
    public ResponseEntity<Object> listarUsuarios() {
        return ResponseEntity.ok(usuarioServicio.listarUsuarios());
    }

    @GetMapping("/me")
    public ResponseEntity<Usuario> getCurrentUser(@AuthenticationPrincipal UserDetails userDetails) {
        Optional<Usuario> usuarioBuscado = usuarioServicio.buscarUsuarioPorEmail(userDetails.getUsername());
        if (usuarioBuscado.isPresent()) {
            return ResponseEntity.ok(usuarioBuscado.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PutMapping("/actualizar/{id}")
    public ResponseEntity<Usuario> actualizarUsuario(
            @PathVariable Long id,
            @Valid @RequestBody UsuarioRegistroDTO usuarioDTO
    ) {
        Optional<Usuario> usuarioExistente = usuarioServicio.buscarUsuarioPorID(id);

        if (!usuarioExistente.isPresent()) {
            return ResponseEntity.notFound().build();
        } else {
            Usuario usuarioActualizado = usuarioServicio.actualizarUsuario(id, usuarioDTO);
            return ResponseEntity.ok(usuarioActualizado);
        }
    }

    @PutMapping("/{id}/cambiarRol")
    public ResponseEntity<Usuario> cambiarRol(@PathVariable Long id, @RequestBody Map<String, String> rol) {
        Optional<Usuario> usuarioExistente = usuarioServicio.buscarUsuarioPorID(id);

        if (!usuarioExistente.isPresent()) {
            return ResponseEntity.notFound().build();
        } else {
            Usuario usuarioActualizado = usuarioServicio.cambiarRolUsuario(id, rol.get("rol"));
            return ResponseEntity.ok(usuarioActualizado);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> eliminarUsuario(@PathVariable Long id) {
        Optional<Usuario> usuarioBuscado = usuarioServicio.buscarUsuarioPorID(id);
        if (usuarioBuscado.isPresent()) {
            usuarioServicio.eliminarUsuario(id);
            return ResponseEntity.ok("Usuario eliminado con éxito.");
        } else {
            return ResponseEntity.badRequest().body("El usuario no existe en la base de datos.");
        }
    }
}

