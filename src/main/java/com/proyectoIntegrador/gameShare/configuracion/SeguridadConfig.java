package com.proyectoIntegrador.gameShare.configuracion;

import com.proyectoIntegrador.gameShare.seguridad.JwtAutenticacionDeEntrada;
import com.proyectoIntegrador.gameShare.seguridad.JwtFiltroDeAutenticacion;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SeguridadConfig {
    private JwtAutenticacionDeEntrada jwtAutenticacionDeEntrada;
    private final JwtFiltroDeAutenticacion jwtFiltroDeAutenticacion;

    // Bean para configurar el AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Bean para codificar las contraseñas utilizando BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Bean para configurar las políticas de CORS
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Permitimos el origen del frontend
        configuration.setAllowedOrigins(List.of("https://frontendgameshare.up.railway.app"));
        // Permitimos los métodos HTTP necesarios
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        // Permitimos todos los headers
        configuration.setAllowedHeaders(List.of("*"));
        // Permitimos el uso de credenciales (cookies, encabezados de autenticación)
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Aplicamos la configuración de CORS a todas las rutas
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // Bean para configurar la cadena de filtros de seguridad
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(jwtAutenticacionDeEntrada))
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        // Requieren autenticación
                        .requestMatchers(HttpMethod.POST, "/videojuegos/nuevo").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/videojuegos/**").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/videojuegos/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/categorias/nuevo").authenticated()
                        .requestMatchers(HttpMethod.POST, "/alquiler/nuevo").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/alquiler/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/alquiler/**").authenticated()
                        // Permitidos sin autenticación
                        .requestMatchers(HttpMethod.GET, "/videojuegos/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/usuarios/nuevo").permitAll()
                        .requestMatchers(HttpMethod.GET, "/usuarios/**").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/usuarios/**").hasAuthority("ADMINISTRADOR")
                        .requestMatchers(HttpMethod.PUT, "/usuarios/**").hasAuthority("ADMINISTRADOR")
                        .requestMatchers(HttpMethod.POST, "/conectarse").permitAll()
                        .requestMatchers(HttpMethod.POST, "/registrarAdmin").permitAll()
                        .requestMatchers(HttpMethod.GET, "/caracteristicas/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/categorias/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/alquiler/**").permitAll()
                        // Cualquier otra solicitud requiere autenticación
                        .anyRequest().authenticated());

        // Agregamos el filtro JWT antes del filtro de autenticación de nombre de usuario y contraseña
        http.addFilterBefore(jwtFiltroDeAutenticacion, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
