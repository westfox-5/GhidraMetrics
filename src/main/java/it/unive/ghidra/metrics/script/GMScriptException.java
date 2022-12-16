package it.unive.ghidra.metrics.script;

public class GMScriptException extends Exception {
	private static final long serialVersionUID = 1L;

	public GMScriptException(String message) {
		super(message);
	}

	public GMScriptException(String message, Throwable cause) {
		super(message, cause);
	}

}
