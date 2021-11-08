package com.cross.solutions.uaa.core;

import org.springframework.stereotype.Service;

@Service
public class LookupServiceImpl implements LookupService {

  private LookupDao lookupDao;

  public LookupServiceImpl(LookupDao lookupDao) {
    this.lookupDao = lookupDao;
  }

  @Override
  public String accountLookup(String username) {
    return lookupDao.findFirstnameByUsername(username);
  }
}
