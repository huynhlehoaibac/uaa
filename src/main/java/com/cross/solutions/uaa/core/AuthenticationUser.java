package com.cross.solutions.uaa.core;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

public class AuthenticationUser extends org.springframework.security.core.userdetails.User {
  private static final long serialVersionUID = 1L;

  private long id;
  private String firstname;
  private String lastname;

  public AuthenticationUser(
      String username,
      String password,
      String firstname,
      String lastname,
      boolean enabled,
      boolean accountNonExpired,
      boolean credentialsNonExpired,
      boolean accountNonLocked,
      Collection<? extends GrantedAuthority> authorities) {
    super(
        username,
        password,
        enabled,
        accountNonExpired,
        credentialsNonExpired,
        accountNonLocked,
        authorities);

    this.firstname = firstname;
    this.lastname = lastname;
  }

  public long getId() {
    return id;
  }

  public String getFirstname() {
    return firstname;
  }

  public String getLastname() {
    return lastname;
  }

  @Override
  public boolean equals(Object rhs) {
    if (rhs instanceof User) {
      return getUsername().equals(((User) rhs).getUsername());
    }
    return false;
  }

  /** Returns the hashcode of the {@code username}. */
  @Override
  public int hashCode() {
    return getUsername().hashCode();
  }
}
