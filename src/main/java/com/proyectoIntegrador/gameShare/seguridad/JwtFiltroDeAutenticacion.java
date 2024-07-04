package com.proyectoIntegrador.gameShare.seguridad;

import com.proyectoIntegrador.gameShare.seguridad.DetallesDeUsuarioServicio;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.io.IOException;
import java.util.List;

// Valida la info del token y, de ser exitoso, establece la autenticación del usuario.
@Data
@Component
public class JwtFiltroDeAutenticacion extends OncePerRequestFilter {
    @Autowired
    private DetallesDeUsuarioServicio detallesDeUsuarioServicio;

    @Autowired
    private JwtGenerador jwtGenerador;

    @Autowired
    @Qualifier("handlerExceptionResolver")
    private HandlerExceptionResolver resolver;

    private static final List<String> EXCLUDE_URLS = List.of(
            "/usuarios/nuevo",
            "/conectarse",
            "/registrarAdmin",
            "/categorias/**",
            "/videojuegos/**",
            "/caracteristicas/**",
            "/alquiler/**"
    );

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return EXCLUDE_URLS.stream().anyMatch(path::matches);
    }

    private String obtenerTokenDeSolicitud(HttpServletRequest solicitud) {
        String bearerToken = solicitud.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest solicitud,
                                    HttpServletResponse respuesta,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = obtenerTokenDeSolicitud(solicitud);

            if (StringUtils.hasText(token) && jwtGenerador.validarToken(token)) {
                String emailUsuario = jwtGenerador.obtenerEmailUsuario(token);
                UserDetails detallesDeUsuario = detallesDeUsuarioServicio.loadUserByUsername(emailUsuario);
                List<String> rolDeUsuario = detallesDeUsuario.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

                if (rolDeUsuario.contains("USUARIO") || rolDeUsuario.contains("ADMINISTRADOR")) {
                    UsernamePasswordAuthenticationToken tokenDeAutenticacion = new UsernamePasswordAuthenticationToken(detallesDeUsuario,
                            null, detallesDeUsuario.getAuthorities());

                    tokenDeAutenticacion.setDetails(new WebAuthenticationDetailsSource().buildDetails(solicitud));
                    SecurityContextHolder.getContext().setAuthentication(tokenDeAutenticacion);
                }
            }
            filterChain.doFilter(solicitud, respuesta);
        } catch (Exception e) {
            resolver.resolveException(solicitud, respuesta, null, e);
        }
    }
}
