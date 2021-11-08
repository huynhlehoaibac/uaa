package com.cross.solutions.uaa.core;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("api/lookup")
@RestController
public class LookupController {

  private LookupService lookupService;

  public LookupController(LookupService lookupService) {
    this.lookupService = lookupService;
  }

  @PostMapping("accountlookup")
  public AccountlookupResponse accountLookup(@RequestBody AccountlookupRequest request) {
    String firstname = lookupService.accountLookup(request.getUsername());
    AccountlookupResponse response = new AccountlookupResponse();
    response.setFirstname(firstname);
    return response;
  }
}
