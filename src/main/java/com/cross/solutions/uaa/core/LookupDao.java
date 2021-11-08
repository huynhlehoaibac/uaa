package com.cross.solutions.uaa.core;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface LookupDao extends JpaRepository<User, Long> {

  @Query("SELECT u.firstname FROM User u WHERE u.username = :username")
  public String findFirstnameByUsername(@Param("username") String username);
}
