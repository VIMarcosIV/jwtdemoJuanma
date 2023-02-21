package org.iesch.ad.jwtdemo.controlador;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import lombok.extern.slf4j.Slf4j;
import org.apache.el.parser.Token;
import org.iesch.ad.jwtdemo.modelo.AuthenticationReq;
import org.iesch.ad.jwtdemo.modelo.TokenInfo;
import org.iesch.ad.jwtdemo.servicio.JwtService;
import org.iesch.ad.jwtdemo.servicio.UsuarioDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Slf4j
public class RestJwtControler {

    @Autowired
    JwtService jwtService;

    @GetMapping("/publico/genera")
    public ResponseEntity<?> genera(){
        String jwt = jwtService.creaJwt();
        Map<String,String>  contenido = new HashMap<>();
        contenido.put("jwt",jwt);
        return ResponseEntity.ok(contenido);

    }

    @GetMapping("/publico/comprueba")
    public ResponseEntity<?> comprueba (@RequestParam String jwt){

        Jws<Claims> nuestroJwt = jwtService.parseJwt(jwt);
        return ResponseEntity.ok(nuestroJwt);
    }

    @GetMapping("/admin")
    public ResponseEntity<?> getMensajeAdmin(){
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Datos del usuario: {}", auth.getPrincipal());
        log.info("Datos de los permisos {}", auth.getAuthorities());
        log.info("Está autenticado {}", auth.isAuthenticated());
        Map<String,String> mensaje = new HashMap<>();
        mensaje.put("Contenido", "Mensaje que solo verá el administrador");
        return ResponseEntity.ok(mensaje);
    }

    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UsuarioDetailsService usuarioDetailService;

    //Endpoint para poder pasar usuario y password
    @PostMapping("/publico/authenticate")
    public ResponseEntity<?> authenticate (@RequestBody AuthenticationReq authenticationReq){

        log.info("Autenticando al usuario {}", authenticationReq.getUsuario());
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
                (authenticationReq.getUsuario(), authenticationReq.getClave()));
        final UserDetails userDetails = usuarioDetailService.loadUserByUsername(authenticationReq.getUsuario());

        final String jwt = jwtService.generateToken(userDetails);

        log.info(userDetails.toString());
        TokenInfo tokenInfo = new TokenInfo(jwt);
        return ResponseEntity.ok(tokenInfo);
    }


}
