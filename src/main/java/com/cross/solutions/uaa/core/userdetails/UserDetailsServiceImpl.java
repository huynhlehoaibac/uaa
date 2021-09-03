package com.cross.solutions.uaa.core.userdetails;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.cross.solutions.uaa.core.User;
import com.cross.solutions.uaa.core.UserRepository;

import lombok.extern.slf4j.Slf4j;

/**
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
@Slf4j
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  @Autowired private MessageSourceAccessor messages;

  @Autowired private UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    if (user == null) {
      log.debug("Query returned no results for user '" + username + "'");
      throw new UsernameNotFoundException(
          messages.getMessage(
              "UserDetailsServiceImpl.notFound",
              new Object[] {username},
              "Username {0} not found"));
    }
    List<GrantedAuthority> authorities =
        AuthorityUtils.commaSeparatedStringToAuthorityList(user.getAuthorities());
    if (authorities.size() == 0) {
      log.debug("User '" + username + "' has no authorities and will be treated as 'not found'");
      throw new UsernameNotFoundException(
          messages.getMessage(
              "UserDetailsServiceImpl.noAuthority",
              new Object[] {username},
              "User {0} has no GrantedAuthority"));
    }

    return new org.springframework.security.core.userdetails.User(
        user.getUsername(), user.getPassword(), authorities);
  }
}
