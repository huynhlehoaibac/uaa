package com.cross.solutions.uaa.core;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
@EnableWebSecurity
public class SecurityConfiguration {

  @Bean
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/h2-console/**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .formLogin(Customizer.withDefaults());
    http.csrf().disable();
    http.headers().frameOptions().disable();
    return http.build();
  }

//  @Bean
//  public UserDetailsService users() {
//    UserDetails user =
//        org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
//            .username("user1")
//            .password("password")
//            .roles("user", "admin")
//            .build();
//    return new InMemoryUserDetailsManager(user);
//  }
}
