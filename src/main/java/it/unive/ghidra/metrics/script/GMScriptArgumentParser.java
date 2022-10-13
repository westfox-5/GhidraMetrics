package it.unive.ghidra.metrics.script;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.script.GMScriptArgument.GMScriptArgumentOption;

public final class GMScriptArgumentParser {
	private static final String ARG_VALUE_SEPARATOR = "=";

	protected static Map<GMScriptArgumentOption, GMScriptArgument<?>> parse(String... args) {
		Map<GMScriptArgumentOption, GMScriptArgument<?>> map = new HashMap<>();

		if (args != null && args.length > 0) {
			List.of(args).forEach(token -> {
				var arg = parseToken(token);
				map.put(arg.getOption(), arg);
			});
		}

		/// validation
		validateAllRequiredArgs(map);

		validateAllCoupledArgs(map);

		return map;
	}

	@SuppressWarnings("unchecked")
	private static <T> GMScriptArgument<T> parseToken(String token) {
		String[] split = token.split(ARG_VALUE_SEPARATOR);

		// only a single value is allowed!
		if (split.length != 2)
			throw new IllegalArgumentException("Invalid argument name or value: " + token);

		String argName = split[0];
		String argValue = split[1];

		var arg = (GMScriptArgument<T>) GMScriptArgument.byName(argName);
		arg.setTypedValue(argValue);

		return arg;
	}

	private static void validateAllRequiredArgs(Map<GMScriptArgumentOption, GMScriptArgument<?>> args) {
		Stream.of(GMScriptArgumentOption.values()).parallel()
				.filter(opt -> opt.isRequired() && opt.getParent() == null && !args.containsKey(opt)).forEach(opt -> {
					throwRequiredParameterMissing(opt);
				});
	}

	private static void validateAllCoupledArgs(Map<GMScriptArgumentOption, GMScriptArgument<?>> args) {
		Stream.of(GMScriptArgumentOption.values()).parallel().filter(opt -> opt.isRequired() && !args.containsKey(opt))
				.filter(opt -> opt.getParent() != null && args.containsKey(opt.getParent())).forEach(opt -> {
					throwRequiredParameterCouple(opt.getParent(), opt);
				});
	}

	private static void throwRequiredParameterCouple(GMScriptArgumentOption arg1, GMScriptArgumentOption arg2) {
		throw new IllegalArgumentException(
				"Missing parameter '" + arg2.getOption() + "' required by parameter '" + arg1.getOption() + "'");
	}

	private static void throwRequiredParameterMissing(GMScriptArgumentOption arg) {
		throw new IllegalArgumentException("Missing a required parameter: '" + arg.getOption() + "'");
	}
}