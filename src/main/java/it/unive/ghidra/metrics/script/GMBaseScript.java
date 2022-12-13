package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

public abstract class GMBaseScript extends GhidraScript {

	private final Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> _args = new HashMap<>();

	protected void parseArgs() throws ScriptException {
		Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> parsed = GMScriptArgumentParser.parse(getScriptArgs());
		_args.putAll(parsed);
	}

	@SuppressWarnings("unchecked")
	private <T> GMScriptArgumentContainer<T> getArg(GMScriptArgumentKey option) {
		return (GMScriptArgumentContainer<T>) _args.get(option);
	}

	public boolean hasArg(GMScriptArgumentKey option) {
		return _args.containsKey(option);
	}

	@SuppressWarnings("unchecked")
	public <T> T getArgValue(GMScriptArgumentKey option) {
		return hasArg(option) ? (T) getArg(option).getValue() : null;
	}
}
