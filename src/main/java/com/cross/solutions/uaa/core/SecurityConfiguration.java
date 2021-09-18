package com.cross.solutions.uaa.core;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
  private static final String TOKEN_BASED_AUTHENTICATION_ENTRY_POINT = "/api/**";
  private static final String LOGIN_PROCESSING_URL = "/api/auth/login";

  @Autowired private DefaultAuthenticationSuccessHandler defaultSuccessHandler;
  @Autowired private DefaultAuthenticationFailureHandler defaultFailureHandler;

  @Autowired private UserDetailsService userDetailsService;
  @Autowired private JwtAuthenticationProvider jwtAuthenticationProvider;

  @Bean(BeanIds.AUTHENTICATION_MANAGER)
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.requestMatcher(new AntPathRequestMatcher(TOKEN_BASED_AUTHENTICATION_ENTRY_POINT))
        .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .csrf(CsrfConfigurer::disable)
        .authorizeRequests(
            ar -> ar.antMatchers(LOGIN_PROCESSING_URL).permitAll().anyRequest().authenticated())
        .addFilterBefore(
            usernamePasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
    //
    ;
  }

  private UsernamePasswordAuthenticationFilter usernamePasswordAuthenticationFilter()
      throws Exception {
    UsernamePasswordAuthenticationFilter filter = new UsernamePasswordAuthenticationFilter();
    filter.setFilterProcessesUrl(LOGIN_PROCESSING_URL);
    filter.setAuthenticationManager(authenticationManagerBean());
    filter.setAuthenticationSuccessHandler(defaultSuccessHandler);
    filter.setAuthenticationFailureHandler(defaultFailureHandler);
    return filter;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
    auth.authenticationProvider(jwtAuthenticationProvider);
  }
}
