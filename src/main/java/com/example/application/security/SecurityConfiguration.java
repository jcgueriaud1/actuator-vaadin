package com.example.application.security;

import com.example.application.views.login.LoginView;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration {
 //https://www.baeldung.com/spring-security-multiple-entry-points

    @Configuration
    @Order(2)
    public static class App1ConfigurationAdapter {

        @Bean
        public SecurityFilterChain filterChainApp1(HttpSecurity http) throws Exception {
            http.csrf().disable().authorizeHttpRequests()
                    .requestMatchers(new AntPathRequestMatcher("/actuator/**")).hasRole("ADMIN")
                    .requestMatchers(new AntPathRequestMatcher("/**")).permitAll()
                    .and().httpBasic();
            return http.build();
        }

    }


    @Configuration
    @Order(1)
    public static class App2ConfigurationAdapter extends VaadinWebSecurity {

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
        @Override
        protected void configure(HttpSecurity http) throws Exception {

            http.authorizeHttpRequests().requestMatchers(new AntPathRequestMatcher("/actuator/**")).permitAll();
            super.configure(http);
            setLoginView(http, LoginView.class);
            http.logout()
                    .invalidateHttpSession(true);
        }
    }

}
