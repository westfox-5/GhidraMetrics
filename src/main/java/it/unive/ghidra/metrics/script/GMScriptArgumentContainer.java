package it.unive.ghidra.metrics.script;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;

/**
 * 
 * Argument holder (typed)
 *
 */
public abstract class GMScriptArgumentContainer<T> {

	private static final Map<GMScriptArgumentContainer.GMScriptArgumentKey, GMScriptArgumentContainer<?>> lookupByKey = new HashMap<>();

	
	/**
	 * Argument keys definition
	 */
	public static enum GMScriptArgumentKey {
		//@formatter:off
		METRIC("metric"), 
		FUNCTION("function"),
		EXPORT("export"),
		EXPORT_DIR("export-dir");
		
		//@formatter:on		
		private final String key;

		private GMScriptArgumentKey(String key) {
			this.key = key;
		}

		public String getKey() {
			return key;
		}

		private static final Map<String, GMScriptArgumentContainer.GMScriptArgumentKey> lookupByOption;
		static {
			lookupByOption = new HashMap<>();
			for (GMScriptArgumentContainer.GMScriptArgumentKey key : GMScriptArgumentKey.values()) {
				lookupByOption.put(key.key, key);
			}
		}

		public static final GMScriptArgumentContainer.GMScriptArgumentKey of(String name) {
			return lookupByOption.get(name);
		}
	}


	// -------------------
	// ARG_DEFAULT
	// -------------------
	// -- Name: null
	// -- Type: Object
	//
	public static final GMScriptArgumentContainer<Object> ARG_DEFAULT = new GMScriptArgumentContainer<>(null) {
		@Override
		protected Object getTypedValue(String str) {
			throw new RuntimeException("ERROR: invoked getTypedValue on default argument!");
		}
	};

	// -----------------------
	// ARG_METRIC_NAME
	// -----------------------
	// -- Name: METRIC
	// -- Type: String
	//
	//@formatter:off
	public static final GMScriptArgumentContainer<String> ARG_METRIC = new GMScriptArgumentContainer<>(GMScriptArgumentKey.METRIC) {
	//@formatter:on
		@Override
		protected String getTypedValue(String str) {
			return str;
		}
	};

	// -----------------------
	// ARG_EXPORT_TYPE
	// -----------------------
	// -- Name: EXPORT
	// -- Type: GMExporter.Type
	//
	//@formatter:off
	public static final GMScriptArgumentContainer<GMMetricExporter.FileFormat> ARG_EXPORT = new GMScriptArgumentContainer<>(GMScriptArgumentKey.EXPORT) {
	//@formatter:on
		@Override
		protected GMMetricExporter.FileFormat getTypedValue(String str) throws GMScriptException {
			try {
				return GMMetricExporter.FileFormat.valueOf(str.toUpperCase());
			} catch (IllegalArgumentException e) {
				String allowedTypes = Stream.of(GMMetricExporter.FileFormat.values())
						.map(type -> type.name().toLowerCase())
						.collect(Collectors.joining(","));
				throw new GMScriptException("No export defined for value '" + str + "'. Please use one of: " + allowedTypes);
			}
		}
	};
	
	// -----------------------
	// ARG_EXPORT_DIR
	// -----------------------
	// -- Name: EXPORT_DIR
	// -- Type: Path
	//
	//@formatter:off
	public static final GMScriptArgumentContainer<Path> ARG_EXPORT_DIR = new GMScriptArgumentContainer<>(GMScriptArgumentKey.EXPORT_DIR) {
	//@formatter:on
		@Override
		protected Path getTypedValue(String str) throws GMScriptException {
			return Path.of(str);
		}
	};

	// -----------------------
	// ARG_FUNCTION
	// -----------------------
	// -- Name: FUNCTION
	// -- Type: String
	//
	//@formatter:off
	public static final GMScriptArgumentContainer<String> ARG_FUNCTION = new GMScriptArgumentContainer<>(GMScriptArgumentKey.FUNCTION) {
	//@formatter:on
		@Override
		protected String getTypedValue(String str) {
			return str;
		}
	};
	
	

	public static final GMScriptArgumentContainer<?> byName(String name) {
		return lookupByKey.getOrDefault(GMScriptArgumentKey.of(name), ARG_DEFAULT);
	}

	private final GMScriptArgumentContainer.GMScriptArgumentKey key;
	private T value;

	private GMScriptArgumentContainer(GMScriptArgumentContainer.GMScriptArgumentKey key) {
		this.key = key;

		lookupByKey.put(key, this);
	}

	protected abstract T getTypedValue(String str) throws GMScriptException;

	protected void setTypedValue(String str) throws GMScriptException {
		this.value = getTypedValue(str);
	}

	public T getValue() {
		return value;
	}

	public GMScriptArgumentContainer.GMScriptArgumentKey getKey() {
		return key;
	}
}