package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.impl.mccabe.GMMcCabe;
import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

public final class GMScriptArgumentParser {
	private static final String ARG_VALUE_SEPARATOR = "=";

	protected static Map<GMScriptArgumentOption, GMScriptArgument<?>> parse(String... args) throws ScriptException {
		Map<GMScriptArgumentOption, GMScriptArgument<?>> map = new HashMap<>();

		if (args != null && args.length > 0) {
			for (String token : args) {
				GMScriptArgument<?> arg = parseToken(token);
				map.put(arg.getOption(), arg);
			}
		}

		/// validation
		validateAllRequiredArgs(map);

		validateAllCoupledArgs(map);

		validateCustomArgs(map);

		return map;
	}

	private static <T> GMScriptArgument<?> parseToken(String token) throws ScriptException {
		String[] split = token.split(ARG_VALUE_SEPARATOR);

		// only a single value is allowed!
		if (split.length != 2)
			throw new IllegalArgumentException("Invalid argument name or value: " + token);

		String argName = split[0];
		String argValue = split[1];

		GMScriptArgument<?> arg = GMScriptArgument.byName(argName);
		arg.setTypedValue(argValue);

		return arg;
	}

	private static void validateAllRequiredArgs(Map<GMScriptArgumentOption, GMScriptArgument<?>> args)
			throws ScriptException.MissingRequiredScriptArgumentException {

		// find options that are required but not defined
		List<GMScriptArgumentOption> missingOpts = Stream.of(GMScriptArgumentOption.values()).parallel()
				.filter(opt -> opt.isRequired() && opt.getParent() == null && !args.containsKey(opt))
				.collect(Collectors.toUnmodifiableList());

		if (missingOpts != null) {
			for (GMScriptArgumentOption opt : missingOpts) {
				throw new ScriptException.MissingRequiredScriptArgumentException(opt);
			}
		}
	}

	private static void validateAllCoupledArgs(Map<GMScriptArgumentOption, GMScriptArgument<?>> args)
			throws ScriptException.MissingRequiredScriptArgumentPairException {

		// find options that are required but not defined when the parent option is
		// defined
		List<GMScriptArgumentOption> missingCoupledOpts = Stream.of(GMScriptArgumentOption.values()).parallel()
				.filter(opt -> opt.isRequired() && !args.containsKey(opt))
				.filter(opt -> opt.getParent() != null && args.containsKey(opt.getParent()))
				.collect(Collectors.toUnmodifiableList());

		if (missingCoupledOpts != null) {
			for (GMScriptArgumentOption opt : missingCoupledOpts) {
				throw new ScriptException.MissingRequiredScriptArgumentPairException(opt);
			}
		}
	}

	private static void validateCustomArgs(Map<GMScriptArgumentOption, GMScriptArgument<?>> args)
			throws ScriptException {

		/// McCabe metric needs a function name
		GMScriptArgument<?> metricNameArg = args.get(GMScriptArgumentOption.METRIC_NAME);
		if (metricNameArg.getValue().equals(GMMcCabe.NAME)) {
			if (!args.containsKey(GMScriptArgumentOption.FUNCTION_NAME)) {
				throw new ScriptException("Missing parameter '" + GMScriptArgumentOption.FUNCTION_NAME.getOption()
						+ "' required for metric '" + metricNameArg.getValue() + "'");
			}
		}

	}
}