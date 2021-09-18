package com.cross.solutions.uaa.core;

import java.io.Serializable;

public interface JwtToken extends Serializable {

  String getToken();
}
