package it.unive.ghidra.metrics.script;

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
public abstract class GMScriptArgumentContainer<T> {

	private static final Map<GMScriptArgumentContainer.GMScriptArgumentKey, GMScriptArgumentContainer<?>> lookupByKey = new HashMap<>();

	
	/**
	 * Argument keys definition
	 */
	public static enum GMScriptArgumentKey {
		//@formatter:off
		METRIC("metric"), 
		FUNCTION("function"),
		EXPORT("export");
		
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
	public static final GMScriptArgumentContainer<Object> ARG_DEFAULT = new GMScriptArgumentContainer<>(null) {
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
	// -- Name: EXPORT_TYPE
	// -- Type: GMExporter.Type
	//@formatter:off
	public static final GMScriptArgumentContainer<GMExporter.Type> ARG_EXPORT = new GMScriptArgumentContainer<>(GMScriptArgumentKey.EXPORT) {
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
	// ARG_FUNCTION_NAME
	// -----------------------
	// -- Name: FUNCTION_NAME
	// -- Type: String
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

	protected abstract T getTypedValue(String str) throws ScriptException;

	protected void setTypedValue(String str) throws ScriptException {
		this.value = getTypedValue(str);
	}

	public T getValue() {
		return value;
	}

	public GMScriptArgumentContainer.GMScriptArgumentKey getKey() {
		return key;
	}
}