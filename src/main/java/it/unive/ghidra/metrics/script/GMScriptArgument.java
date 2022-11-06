package it.unive.ghidra.metrics.script;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.export.GMExporter.Type;
import it.unive.ghidra.metrics.script.exceptions.ScriptException;

/**
 * 
 * Argument holder (typed)
 *
 */
public abstract class GMScriptArgument<T> {

	/**
	 * Argument option definition
	 */
	public static enum GMScriptArgumentOption {
		//@formatter:off
		METRIC_NAME("metricName", true), 
		FUNCTION_NAME("functionName", false, GMScriptArgumentOption.METRIC_NAME),
		EXPORT_TYPE("exportType"), 
		EXPORT_PATH("exportPath", true, GMScriptArgumentOption.EXPORT_TYPE);
		//@formatter:on		
		private final String option;
		private final boolean required;
		private final GMScriptArgumentOption parent;

		private GMScriptArgumentOption(String option, boolean required, GMScriptArgumentOption parent) {
			this.option = option;
			this.required = required;
			this.parent = parent;
		}

		private GMScriptArgumentOption(String option) {
			this(option, false, null);
		}

		private GMScriptArgumentOption(String option, boolean required) {
			this(option, required, null);
		}

		private GMScriptArgumentOption(String option, GMScriptArgumentOption parent) {
			this(option, false, parent);
		}

		public String getOption() {
			return option;
		}

		public boolean isRequired() {
			return required;
		}

		public GMScriptArgumentOption getParent() {
			return parent;
		}

		private static final Map<String, GMScriptArgument.GMScriptArgumentOption> lookupByOption;
		static {
			lookupByOption = new HashMap<>();
			for (GMScriptArgument.GMScriptArgumentOption argName : GMScriptArgumentOption.values()) {
				lookupByOption.put(argName.option, argName);
			}
		}

		public static final GMScriptArgument.GMScriptArgumentOption of(String name) {
			return lookupByOption.get(name);
		}
	}

	private static final Map<GMScriptArgument.GMScriptArgumentOption, GMScriptArgument<?>> lookupByOption = new HashMap<>();

	// -------------------
	// ARG_DEFAULT
	// -------------------
	// -- Name: null
	// -- Type: Object
	public static final GMScriptArgument<Object> ARG_DEFAULT = new GMScriptArgument<>(null) {
		@Override
		protected Object getTypedValue(String str) {
			throw new RuntimeException("ERROR: invoked getTypedValue on default argument!");
		}
	};

	// -----------------------
	// ARG_METRIC_NAME
	// -----------------------
	// -- Name: METRIC_NAME
	// -- Type: String
	//@formatter:off
	public static final GMScriptArgument<String> ARG_METRIC_NAME = new GMScriptArgument<>(GMScriptArgumentOption.METRIC_NAME) {
	//@formatter:on
		@Override
		protected String getTypedValue(String str) {
			return str;
		}
	};

	// -----------------------
	// ARG_EXPORT_TYPE
	// -----------------------
	// -- Name: EXPORT_TYPE
	// -- Type: GMExporter.Type
	//@formatter:off
	public static final GMScriptArgument<GMExporter.Type> ARG_EXPORT_TYPE = new GMScriptArgument<>(GMScriptArgumentOption.EXPORT_TYPE) {
	//@formatter:on
		@Override
		protected Type getTypedValue(String str) throws ScriptException {
			try {
				return GMExporter.Type.valueOf(str.toUpperCase());
			} catch (IllegalArgumentException e) {
				String allowedTypes = Stream.of(GMExporter.Type.values())
						.map(type -> type.name().toLowerCase())
						.collect(Collectors.joining(","));
				throw new ScriptException("No export defined for value '" + str + "'. Please use one of: " + allowedTypes);
			}
		}
	};

	// -----------------------
	// ARG_EXPORT_PATH
	// -----------------------
	// -- Name: EXPORT_PATH
	// -- Type: Path
	//@formatter:off
	public static final GMScriptArgument<Path> ARG_EXPORT_PATH = new GMScriptArgument<>(GMScriptArgumentOption.EXPORT_PATH) {
	//@formatter:on
		@Override
		protected Path getTypedValue(String str) {
			return Paths.get(str);
		}
	};

	// -----------------------
	// ARG_FUNCTION_NAME
	// -----------------------
	// -- Name: FUNCTION_NAME
	// -- Type: String
	//@formatter:off
	public static final GMScriptArgument<String> ARG_FUNCTION_NAME = new GMScriptArgument<>(GMScriptArgumentOption.FUNCTION_NAME) {
	//@formatter:on
		@Override
		protected String getTypedValue(String str) {
			return str;
		}
	};

	public static final GMScriptArgument<?> byName(String name) {
		return lookupByOption.getOrDefault(GMScriptArgumentOption.of(name), ARG_DEFAULT);
	}

	private final GMScriptArgument.GMScriptArgumentOption option;
	private T value;

	private GMScriptArgument(GMScriptArgument.GMScriptArgumentOption option) {
		this.option = option;

		lookupByOption.put(option, this);
	}

	protected abstract T getTypedValue(String str) throws ScriptException;

	protected void setTypedValue(String str) throws ScriptException {
		this.value = getTypedValue(str);
	}

	public T getValue() {
		return value;
	}

	public GMScriptArgument.GMScriptArgumentOption getOption() {
		return option;
	}
}