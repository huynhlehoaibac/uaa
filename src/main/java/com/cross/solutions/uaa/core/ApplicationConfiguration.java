package com.cross.solutions.uaa.core;

import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

/**
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
@Configuration
public class ApplicationConfiguration {

  @Bean
  public LocaleResolver getLocaleResolver() {
    return new AcceptHeaderLocaleResolver();
  }

  @Bean
  public MessageSourceAccessor messageSourceAccessor(MessageSource messageSource) {
    return new MessageSourceAccessor(messageSource);
  }
}
