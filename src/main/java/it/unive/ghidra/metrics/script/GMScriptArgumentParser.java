package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentName;

public final class GMScriptArgumentParser {
	private static final String ARG_VALUE_SEPARATOR = "=";
	
	protected static Map<GMScriptArgumentName, GMScriptArgument<?>> parse(String... args) {
		Map<GMScriptArgumentName, GMScriptArgument<?>> map = new HashMap<>();
		
		if (args != null && args.length>0) {			
			List.of(args).forEach( token -> {
				var arg = parseToken(token);
				map.put(arg.getName(), arg);
			});
		}
		
		return map;
	}
	
	@SuppressWarnings("unchecked")
	private static <T> GMScriptArgument<T> parseToken(String token) {
		String[] split = token.split(ARG_VALUE_SEPARATOR);

		// only a single value is allowed!
		if (split.length != 2) 
			throw new IllegalArgumentException("Invalid argument name or value: "+ token);
		
		String argName = split[0];
		String argValue = split[1];
		
		var arg = (GMScriptArgument<T>) GMScriptArgument.byName(argName);
		arg.setTypedValue(argValue);
		
		return arg;
	}
	
}