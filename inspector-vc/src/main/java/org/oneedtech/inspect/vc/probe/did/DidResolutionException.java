package org.oneedtech.inspect.vc.probe.did;

public class DidResolutionException extends Exception {

  private static final long serialVersionUID = 1L;

  public DidResolutionException(String message) {
    super(message);
  }

  public DidResolutionException(String message, Throwable cause) {
    super(message, cause);
  }

}
