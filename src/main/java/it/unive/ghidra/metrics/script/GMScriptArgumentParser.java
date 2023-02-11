package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.Map;

import it.unive.ghidra.metrics.impl.similarity.GMSimilarity;

public final class GMScriptArgumentParser {
	private static final String ARG_VALUE_SEPARATOR = "=";

	public static Map<GMScriptArgument<?>, String> parse(String... args) throws GMScriptException {
		Map<GMScriptArgument<?>, String> map = new HashMap<>();

		if (args != null && args.length > 0) {
			for (String token : args) {
				String[] split = token.split(ARG_VALUE_SEPARATOR);

				// only a single value is allowed!
				if (split.length != 2) {
					throw new IllegalArgumentException("Invalid argument name or value: " + token);
				}

				String argName = split[0];
				String argValue = split[1];

				GMScriptArgument<?> arg = GMScriptArgument.byArgName(argName);
				map.put(arg, argValue);
			}
		}

		validate(map);

		return map;
	}

	private static void validate(Map<GMScriptArgument<?>, String> map) throws GMScriptException {

		final String metricName = GMScriptArgument.ARG_METRIC.getTypedValue(map.get(GMScriptArgument.ARG_METRIC));
		
		/// McCabe metric needs a function name
//		if (metricName.equalsIgnoreCase(GMMcCabe.NAME)) {
//			if (!map.containsKey(GMScriptArgument.ARG_FUNCTION)) {
//				throw new GMScriptException("Missing parameter '" + GMScriptArgument.ARG_FUNCTION + "' "
//						+ "required by metric '" + metricName + "'");
//			}
//		}

		/// Similarity needs similarity-input and similarity-zipper
		if (metricName.equalsIgnoreCase(GMSimilarity.NAME)) {
			if (!map.containsKey(GMScriptArgument.ARG_SIMILARITY_INPUT)) {
				throw new GMScriptException("Missing parameter '" + GMScriptArgument.ARG_SIMILARITY_INPUT + "' "
						+ "required by metric '" + metricName + "'");
			}
			
			if (!map.containsKey(GMScriptArgument.ARG_SIMILARITY_ZIPPER)) {
				throw new GMScriptException("Missing parameter '" + GMScriptArgument.ARG_SIMILARITY_ZIPPER + "' "
						+ "required by metric '" + metricName + "'");
			}
		}

	}
}