package it.unive.ghidra.metrics.base;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer;
import it.unive.ghidra.metrics.script.GMScriptArgumentParser;
import it.unive.ghidra.metrics.script.GMScriptException;
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;

public abstract class GMBaseScript extends GhidraScript {

	private final Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> args = new HashMap<>();

	protected void parseArgs() throws GMScriptException {
		Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> parsed = GMScriptArgumentParser.parse(getScriptArgs());
		args.putAll(parsed);
	}

	@SuppressWarnings("unchecked")
	private <T> GMScriptArgumentContainer<T> getArg(GMScriptArgumentKey option) {
		return (GMScriptArgumentContainer<T>) args.get(option);
	}

	public boolean hasArg(GMScriptArgumentKey option) {
		return args.containsKey(option);
	}

	@SuppressWarnings("unchecked")
	public <T> T getArgValue(GMScriptArgumentKey option) {
		return hasArg(option) ? (T) getArg(option).getValue() : null;
	}
}
