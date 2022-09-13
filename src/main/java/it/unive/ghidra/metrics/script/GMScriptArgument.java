package it.unive.ghidra.metrics.script;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import it.unive.ghidra.metrics.GMExporter;
import it.unive.ghidra.metrics.GMExporter.Type;
import it.unive.ghidra.metrics.base.GMetric;

/**
 * 
 * Argument holder (typed)
 *
 */
public abstract class GMScriptArgument<T> {

	/**
	 * Argument name definition
	 */
	public static enum GMScriptArgumentName {
		METRIC_NAME("metricName"), EXPORT_TYPE("exportType"), EXPORT_PATH("exportPath");
		
		private String name;
		private GMScriptArgumentName(String name) {
			this.name = name;
		}
		
		private static final Map<String, GMScriptArgument.GMScriptArgumentName> lookupByName;
		static {
			lookupByName = new HashMap<>();
			for (GMScriptArgument.GMScriptArgumentName argName: GMScriptArgumentName.values()) {
				lookupByName.put(argName.name, argName);
			}
		}
		public static final GMScriptArgument.GMScriptArgumentName of(String name) {
			return lookupByName.get(name);
		}
	}
	
	private static final Map<GMScriptArgument.GMScriptArgumentName, GMScriptArgument<?>> lookupByName = new HashMap<>();

	// -------------------
	//     ARG_DEFAULT
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
	//      ARG_METRIC_NAME
	// -----------------------
	// -- Name: METRIC_NAME 
	// -- Type: Class<? extends GMetric>
	public static final GMScriptArgument<Class<? extends GMetric>> ARG_METRIC_NAME = new GMScriptArgument<>(GMScriptArgumentName.METRIC_NAME) {
		@Override
		protected Class<? extends GMetric> getTypedValue(String str) {
			return GMetric.metricByName(str);
		}
	};
	
	// -----------------------
	//     ARG_EXPORT_TYPE
	// -----------------------
	// -- Name: EXPORT_TYPE 
	// -- Type: GMExporter.Type
	public static final GMScriptArgument<GMExporter.Type> ARG_EXPORT_TYPE = new GMScriptArgument<>(GMScriptArgumentName.EXPORT_TYPE) {
		@Override
		protected Type getTypedValue(String str) {
			return GMExporter.Type.valueOf(str);
		}
	};
	
	// -----------------------
	//     ARG_EXPORT_PATH
	// -----------------------
	// -- Name: EXPORT_PATH 
	// -- Type: Path
	public static final GMScriptArgument<Path> ARG_EXPORT_PATH = new GMScriptArgument<>(GMScriptArgumentName.EXPORT_PATH) {
		@Override
		protected Path getTypedValue(String str) {
			return Paths.get(str);
		}

	};
	
	public static final GMScriptArgument<?> byName(String name) {
		return lookupByName.getOrDefault(GMScriptArgumentName.of(name), ARG_DEFAULT);
	}

	
	private final GMScriptArgument.GMScriptArgumentName name;
	private T value;
	
	private GMScriptArgument(GMScriptArgument.GMScriptArgumentName name) {
		this.name = name;
		
		lookupByName.put(name, this);
	}
	
	protected abstract T getTypedValue(String str);
	
	protected void setTypedValue(String str) {
		this.value = getTypedValue(str);
	}
	
	protected T getValue() {
		return value;
	}

	public GMScriptArgument.GMScriptArgumentName getName() {
		return name;
	}
}