package it.unive.ghidra.metrics.script;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMZipper;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter.FileFormat;
import it.unive.ghidra.metrics.impl.GhidraMetricFactory;

/**
 * 
 * Argument definition (typed)
 *
 */
public abstract class GMScriptArgument<T> {

	private static final Map<String, GMScriptArgument<?>> lookupByKey = new HashMap<>();
	private static final String ARGNAME_METRIC = "metric";
	private static final String ARGNAME_FUNCTION = "function";
	private static final String ARGNAME_EXPORT = "export";
	private static final String ARGNAME_EXPORT_DIR = "export-dir";
	private static final String ARGNAME_SIMILARITY_INPUT = "similarity-input";
	private static final String ARGNAME_SIMILARITY_ZIPPER = "similarity-zipper";

	// -------------------
	// ARG_DEFAULT
	// -------------------
	// -- Name: null
	// -- Type: Object
	//
	public static final GMScriptArgument<Object> ARG_DEFAULT = new GMScriptArgument<>(null) {
		@Override
		public Object getTypedValue(String str) {
			throw new RuntimeException("ERROR: invoked getTypedValue on default argument!");
		}

		@Override
		public Class<Object> getTypeClass() {
			throw new RuntimeException("ERROR: invoked getTypeClass on default argument!");
		}
	};

	// -----------------------
	// ARG_METRIC_NAME
	// -----------------------
	// -- Name: metric
	// -- Type: String
	//
	//@formatter:off
	public static final GMScriptArgument<String> ARG_METRIC = new GMScriptArgument<String>(ARGNAME_METRIC) {
	//@formatter:on
		@Override
		public String getTypedValue(String str) {
			return str;
		}

		@Override
		public Class<String> getTypeClass() {
			return String.class;
		}
	};

	// -----------------------
	// ARG_EXPORT_TYPE
	// -----------------------
	// -- Name: export
	// -- Type: GMExporter.Type
	//
	//@formatter:off
	public static final GMScriptArgument<GMMetricExporter.FileFormat> ARG_EXPORT = new GMScriptArgument<>(ARGNAME_EXPORT) {
	//@formatter:on
		@Override
		public GMMetricExporter.FileFormat getTypedValue(String str) throws GMScriptException {
			GMMetricExporter.FileFormat fileFormat = GhidraMetricFactory.getFileFormat(str);
			if (fileFormat == null) {
				String allowedValues = GhidraMetricFactory.allFileFormats().stream().map(name -> name.toLowerCase()).collect(Collectors.joining(","));
				throw new GMScriptException(
						"No export type defined for value '" + str + "'. Please use one of: " + allowedValues);
			}
			return fileFormat;
		}

		@Override
		public Class<FileFormat> getTypeClass() {
			return FileFormat.class;
		}
	};

	// -----------------------
	// ARG_EXPORT_DIR
	// -----------------------
	// -- Name: export-dir
	// -- Type: Path
	//
	//@formatter:off
	public static final GMScriptArgument<Path> ARG_EXPORT_DIR = new GMScriptArgument<>(ARGNAME_EXPORT_DIR) {
	//@formatter:on
		@Override
		public Path getTypedValue(String str) throws GMScriptException {
			return Path.of(str);
		}

		@Override
		public Class<Path> getTypeClass() {
			return Path.class;
		}
	};

	// -----------------------
	// ARG_FUNCTION
	// -----------------------
	// -- Name: function
	// -- Type: String
	//
	//@formatter:off
	public static final GMScriptArgument<String> ARG_FUNCTION = new GMScriptArgument<>(ARGNAME_FUNCTION) {
	//@formatter:on
		@Override
		public String getTypedValue(String str) {
			return str;
		}

		@Override
		public Class<String> getTypeClass() {
			return String.class;
		}
	};

	// -----------------------
	// ARG_SIMILARITY_INPUT
	// -----------------------
	// -- Name: similarity-input
	// -- Type: Path
	//
	//@formatter:off
	public static final GMScriptArgument<Path> ARG_SIMILARITY_INPUT = new GMScriptArgument<>(ARGNAME_SIMILARITY_INPUT) {
	//@formatter:on
		@Override
		public Path getTypedValue(String str) {
			return Path.of(str);
		}

		@Override
		public Class<Path> getTypeClass() {
			return Path.class;
		}
	};
	
	// -----------------------
	// ARG_SIMILARITY_ZIPPER
	// -----------------------
	// -- Name: similarity-zipper
	// -- Type: Path
	//
	//@formatter:off
	public static final GMScriptArgument<GMZipper> ARG_SIMILARITY_ZIPPER = new GMScriptArgument<>(ARGNAME_SIMILARITY_ZIPPER) {
	//@formatter:on
		@Override
		public GMZipper getTypedValue(String str) throws GMScriptException {
			GMZipper zipper = GhidraMetricFactory.getZipper(str);
			if (zipper == null) {
				String allowedValues = GhidraMetricFactory.allZippers().stream().map(name -> name.toLowerCase()).collect(Collectors.joining(","));
				throw new GMScriptException(
						"No zipper function defined for value '" + str + "'. Please use one of: " + allowedValues);
			}
			return zipper;
		}

		@Override
		public Class<GMZipper> getTypeClass() {
			return GMZipper.class;
		}
	};

	public static final GMScriptArgument<?> byArgName(String argName) {
		return lookupByKey.getOrDefault(argName, ARG_DEFAULT);
	}

	private final String name;

	private GMScriptArgument(String name) {
		this.name = name;
		lookupByKey.put(name, this);
	}
	public abstract T getTypedValue(String str) throws GMScriptException;	
	public abstract Class<T> getTypeClass();

	public String getName() {
		return name;
	}
	@Override
	public int hashCode() {
		return Objects.hash(name);
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GMScriptArgument<?> other = (GMScriptArgument<?>) obj;
		return Objects.equals(name, other.name);
	}

	@Override
	public String toString() {
		return name;
	}
	
	
}