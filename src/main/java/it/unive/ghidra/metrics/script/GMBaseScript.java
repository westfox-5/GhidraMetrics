package it.unive.ghidra.metrics.script;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

public abstract class GMBaseScript extends GhidraScript {

	private final Map<GMScriptArgumentOption, GMScriptArgument<?>> _args = new HashMap<>();
	
	protected abstract String getScriptHelp();
	
	protected abstract List<GMScriptArgumentOption> getScriptOptions();

	protected void parseArgs() throws ScriptException {
		Map<GMScriptArgumentOption, GMScriptArgument<?>> parsed = GMScriptArgumentParser.parse(getScriptOptions(), Arrays.asList(getScriptArgs()));
		_args.putAll(parsed);
	}

	@SuppressWarnings("unchecked")
	private <T> GMScriptArgument<T> getArg(GMScriptArgumentOption option) {
		return (GMScriptArgument<T>) _args.get(option);
	}

	public boolean hasArg(GMScriptArgumentOption option) {
		return _args.containsKey(option);
	}

	@SuppressWarnings("unchecked")
	public <T> T getArgValue(GMScriptArgumentOption option) {
		return hasArg(option) ? (T) getArg(option).getValue() : null;
	}

	public void printHelp() {
		Msg.info(this, getScriptName());
		Msg.info(this, getScriptHelp());
	}

}
