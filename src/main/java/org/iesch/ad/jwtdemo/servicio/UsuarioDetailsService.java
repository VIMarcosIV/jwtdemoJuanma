package org.iesch.ad.jwtdemo.servicio;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@Service
public class UsuarioDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Map<String,String> usuarios = Map.of(
                "juanma", "USER",
                "admin", "ADMIN"
                );
        String rol = usuarios.get(username);
        if (rol != null) {
            User.UserBuilder userBuilder = User.withUsername(username);
            String pass = "{noop}" + "1234";
            userBuilder.password(pass).roles(rol);
            return userBuilder.build();
        }
        else throw new UsernameNotFoundException(username);


    }
}
