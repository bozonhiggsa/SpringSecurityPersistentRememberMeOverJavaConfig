package com.application.springSecurity.config;

import com.application.springSecurity.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * Java configuration of a Spring Security context
 * @author Ihor Savchenko
 * @version 1.0
 */
@EnableWebSecurity
@ComponentScan("com.application.springSecurity")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Bean
    public MyUserDetailsService myUserDetailsService() {
        MyUserDetailsService myUserDetailsService = new MyUserDetailsService(getPasswordEncoder());
        return myUserDetailsService;
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService());
    }

    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/admin/auth").hasAuthority("ROLE_ADMIN")
                .antMatchers("/auth").hasAnyAuthority("ROLE_ADMIN","ROLE_USER")
                .antMatchers("/permit").permitAll()
                .antMatchers("/forbid").denyAll()
                .antMatchers("/anonymous").anonymous()
                .antMatchers("/authenticated").authenticated()
                .antMatchers("/fullyAuthenticated").fullyAuthenticated()
                .antMatchers("/rememberMe").rememberMe()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .rememberMe().tokenRepository(persistentTokenRepository())
                .and()
                .logout().permitAll().logoutUrl("/logout");
        http
                .requiresChannel()
                .antMatchers("/").requiresInsecure()
                .antMatchers("/**").requiresSecure();
    }

    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        final JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        return jdbcTokenRepository;
    }

    @Bean
    public BCryptPasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder(12);
    }

}