package it.unive.ghidra.metrics.script;

import java.util.Map;

import ghidra.app.script.GhidraScript;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentName;

public abstract class GMScript extends GhidraScript {
	
	private final Map<GMScriptArgumentName, GMScriptArgument<?>> _args;
	
	protected GMScript() {
		_args = GMScriptArgumentParser.parse(getScriptArgs());		
	}


	@SuppressWarnings("unchecked")
	public <T> GMScriptArgument<T> getArg(GMScriptArgumentName name) {
		return (GMScriptArgument<T>) _args.get(name);
	}
	
	public boolean hasArg(GMScriptArgumentName name) {
		return _args.containsKey(name);
	}
}
