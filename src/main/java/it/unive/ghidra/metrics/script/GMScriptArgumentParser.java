package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.Map;

import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.script.GMScriptArgumentContainer.GMScriptArgumentKey;

public final class GMScriptArgumentParser {
	private static final String ARG_VALUE_SEPARATOR = "=";

	public static Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> parse(String... args) throws GMScriptException {
		Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> map = new HashMap<>();

		if (args != null && args.length > 0) {
			for (String token : args) {
				GMScriptArgumentContainer<?> arg = parseToken(token);
				map.put(arg.getKey(), arg);
			}
		}

		/// validation

		validateArguments(map);

		return map;
	}

	private static <T> GMScriptArgumentContainer<?> parseToken(String token) throws GMScriptException {
		String[] split = token.split(ARG_VALUE_SEPARATOR);

		// only a single value is allowed!
		if (split.length != 2)
			throw new IllegalArgumentException("Invalid argument name or value: " + token);

		String argName = split[0];
		String argValue = split[1];

		GMScriptArgumentContainer<?> arg = GMScriptArgumentContainer.byName(argName);
		arg.setTypedValue(argValue);

		return arg;
	}



	private static void validateArguments(Map<GMScriptArgumentKey, GMScriptArgumentContainer<?>> args)
			throws GMScriptException {

		/// McCabe metric needs a function name
		GMScriptArgumentContainer<?> metricNameArg = args.get(GMScriptArgumentKey.METRIC);
		if (metricNameArg.getValue().equals(GMMcCabe.NAME)) {
			if (!args.containsKey(GMScriptArgumentKey.FUNCTION)) {
				throw new GMScriptException(
						"Missing parameter '" + GMScriptArgumentKey.FUNCTION.getKey() + "' "
						+ "required for metric '" + metricNameArg.getValue() + "'");
			}
		}

	}
}