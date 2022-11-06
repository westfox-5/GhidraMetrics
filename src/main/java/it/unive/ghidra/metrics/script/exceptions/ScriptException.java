package it.unive.ghidra.metrics.script.exceptions;

import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;

public class ScriptException extends Exception {
	private static final long serialVersionUID = 1L;

	public static class MissingRequiredScriptArgumentException extends ScriptException {
		private static final long serialVersionUID = 1L;

		public MissingRequiredScriptArgumentException(GMScriptArgumentOption opt) {
			super("Missing a required parameter: '" + opt.getOption() + "'");
		}
	}

	public static class MissingRequiredScriptArgumentPairException extends ScriptException {
		private static final long serialVersionUID = 1L;

		public MissingRequiredScriptArgumentPairException(GMScriptArgumentOption opt) {
			super("Missing parameter '" + opt.getParent().getOption() + "' required by parameter '" + opt.getOption() + "'");
		}
	}

	public ScriptException(String message) {
		super(message);
	}

	public ScriptException(String message, Throwable cause) {
		super(message, cause);
	}

}
