package com.application.springSecurity.service;

import com.application.springSecurity.security.SecurityRole;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Custom implementation of UserDetailsService interface
 * @author Ihor Savchenko
 * @version 1.0
 */
public class MyUserDetailsService implements UserDetailsService {

    private final Map<String, User> availableUsers = new HashMap<>();

    public MyUserDetailsService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        populateDemoUsers(bCryptPasswordEncoder);
    }

    @Override
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {

        final UserDetails user = availableUsers.get(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return user;
    }

    /**
     * Create demo users (note: obviously in a real system these would be persisted
     * in database or retrieved from another system).
     */
    private void populateDemoUsers(BCryptPasswordEncoder bCryptPasswordEncoder) {

        availableUsers.put("user", createUser(bCryptPasswordEncoder, "user", "password", Arrays.asList(SecurityRole.ROLE_USER)));
        availableUsers.put("admin", createUser(bCryptPasswordEncoder, "admin", "admin", Arrays.asList(SecurityRole.ROLE_ADMIN)));
    }

    private User createUser(BCryptPasswordEncoder bCryptPasswordEncoder, final String username, final String password, final List<SecurityRole> roles) {

        final List<GrantedAuthority> authorities = roles.stream().map(role -> new SimpleGrantedAuthority(role.toString())).collect(Collectors.toList());

        return new User(username, bCryptPasswordEncoder.encode(password), true, true, true, true, authorities);
    }
}
