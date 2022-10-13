package it.unive.ghidra.metrics.script;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.export.GMExporter.Type;

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
		EXPORT_TYPE("exportType"), EXPORT_PATH("exportPath", true, GMScriptArgumentOption.EXPORT_TYPE);
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
	public static final GMScriptArgument<String> ARG_METRIC_NAME = new GMScriptArgument<>(
			GMScriptArgumentOption.METRIC_NAME) {
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
	public static final GMScriptArgument<GMExporter.Type> ARG_EXPORT_TYPE = new GMScriptArgument<>(
			GMScriptArgumentOption.EXPORT_TYPE) {
		@Override
		protected Type getTypedValue(String str) {
			return GMExporter.Type.valueOf(str);
		}
	};

	// -----------------------
	// ARG_EXPORT_PATH
	// -----------------------
	// -- Name: EXPORT_PATH
	// -- Type: Path
	public static final GMScriptArgument<Path> ARG_EXPORT_PATH = new GMScriptArgument<>(
			GMScriptArgumentOption.EXPORT_PATH) {
		@Override
		protected Path getTypedValue(String str) {
			return Paths.get(str);
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

	protected abstract T getTypedValue(String str);

	protected void setTypedValue(String str) {
		this.value = getTypedValue(str);
	}

	public T getValue() {
		return value;
	}

	public GMScriptArgument.GMScriptArgumentOption getOption() {
		return option;
	}
}