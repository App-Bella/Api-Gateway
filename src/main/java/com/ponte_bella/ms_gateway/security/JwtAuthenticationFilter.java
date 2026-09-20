package com.ponte_bella.ms_gateway.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            if (jwtService.validarToken(token)) {
                String userId = jwtService.obtenerUserId(token);
                String email = jwtService.obtenerEmail(token);
                String rol = jwtService.obtenerRol(token);

                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                if (rol != null && !rol.isBlank()) {
                    String cleanRol = rol.trim().toUpperCase();
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + cleanRol));
                    authorities.add(new SimpleGrantedAuthority(cleanRol));
                }

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userId, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authToken);

                // Decorar request con cabeceras downstream X-User-Id, X-User-Email, X-User-Role
                HeaderMapRequestWrapper wrappedRequest = new HeaderMapRequestWrapper(request);
                if (userId != null) wrappedRequest.addHeader("X-User-Id", userId);
                if (email != null) wrappedRequest.addHeader("X-User-Email", email);
                if (rol != null) wrappedRequest.addHeader("X-User-Role", rol);

                filterChain.doFilter(wrappedRequest, response);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
