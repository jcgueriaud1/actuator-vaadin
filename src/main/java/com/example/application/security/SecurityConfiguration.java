package com.example.application.security;

import com.example.application.views.login.LoginView;
import com.vaadin.flow.spring.security.VaadinWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration {

    @Configuration
    @Order(1)
    public static class ActuatorConfigurationAdapter {

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder();
        }
        @Bean
        public SecurityFilterChain filterActuator(HttpSecurity http) throws Exception {
            // For Vaadin 23 you need to replace this by
            /*http.requestMatcher(new AntPathRequestMatcher("/actuator/**")).authorizeRequests()
                    .requestMatchers(new AntPathRequestMatcher("/actuator/**")).hasRole("ACTUATOR")
                    .and().httpBasic();*/
            http.securityMatcher("/actuator/**").authorizeHttpRequests()
                    .requestMatchers(new AntPathRequestMatcher("/actuator/**")).hasRole("ADMIN")
                    .and().httpBasic();
            return http.build();
        }

    }


    @Configuration
    @Order(2)
    public static class VaadinConfigurationAdapter extends VaadinWebSecurity {

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            // For Vaadin 23 you need to replace authorizeHttpRequests by authorizeRequests
            http.authorizeHttpRequests().requestMatchers(new AntPathRequestMatcher("/error")).permitAll();
            super.configure(http);
            setLoginView(http, LoginView.class);
            http.logout()
                    .invalidateHttpSession(true);
        }
    }

}
