package com.cross.solutions.uaa.core;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;

/**
 * @author huynhlehoaibac
 * @since 0.0.1-SNAPSHOT
 */
@Entity
@Table(
    name = "user",
    schema = "uaa",
    uniqueConstraints = @UniqueConstraint(columnNames = "username"))
public class User implements java.io.Serializable {
  private static final long serialVersionUID = 1L;

  private long id;
  private String username;
  private String password;
  private String authorities;

  public User() {}

  public User(long id, String username, String authorities) {
    this.id = id;
    this.username = username;
    this.authorities = authorities;
  }

  public User(long id, String username, String password, String authorities) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.authorities = authorities;
  }

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  @Column(name = "id", unique = true, nullable = false)
  public long getId() {
    return this.id;
  }

  public void setId(long id) {
    this.id = id;
  }

  @Column(name = "username", unique = true, nullable = false, length = 16)
  public String getUsername() {
    return this.username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  @Column(name = "password", length = 60)
  public String getPassword() {
    return this.password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  @Column(name = "authorities", nullable = false)
  public String getAuthorities() {
    return this.authorities;
  }

  public void setAuthorities(String authorities) {
    this.authorities = authorities;
  }
}
