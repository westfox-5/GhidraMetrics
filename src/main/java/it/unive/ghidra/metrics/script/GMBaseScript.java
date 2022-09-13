package it.unive.ghidra.metrics.script;

import java.util.Map;

import ghidra.app.script.GhidraScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentName;

public abstract class GMBaseScript extends GhidraScript {
	
	private final Map<GMScriptArgumentName, GMScriptArgument<?>> _args;
	
	protected GMBaseScript() {
		_args = GMScriptArgumentParser.parse(getScriptArgs());
	}

	@SuppressWarnings("unchecked")
	public <T> GMScriptArgument<T> getArg(GMScriptArgumentName name) {
		return (GMScriptArgument<T>) _args.get(name);
	}
	
	public boolean hasArg(GMScriptArgumentName name) {
		return _args.containsKey(name);
	}
	
	@SuppressWarnings("unchecked")
	public <T> T getArgValue(GMScriptArgumentName name) {
		if (hasArg(name)) {
			return (T) getArg(name).getValue();
		}
		return null;
	}
}
