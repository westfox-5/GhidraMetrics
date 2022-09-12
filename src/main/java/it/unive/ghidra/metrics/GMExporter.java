package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.serialize.GMSerializer;

public class GMExporter {
	public static enum Type {
		JSON("json", "application/json");
		
		private String ext;
		private String contentType;
		
		private Type(String ext, String contentType) { 
			this.ext = ext;
			this.contentType = contentType;
		}
		
		public String getExtension() {
			return ext;
		}
		public String getContentType() {
			return contentType;
		}
	}

	private static final Path newTemp() throws IOException {
		return Files.createTempFile("ghidra_metrics_export", ".ghidra");
	}
	
	public static final GMExporter of(GMExporter.Type type) { 
		return new GMExporter(type); 
	}
	
	
	private final GMExporter.Type type;
	
	private GMExporter(GMExporter.Type type) {
		this.type = type;
	}
	
	public Path export(GMetric metric) {
		if (metric == null) {
			throw new RuntimeException("ERROR: No metric to export!");
		}
		
		try {
			Path tmp = newTemp();			
			if (Files.notExists(tmp)) {
				throw new RuntimeException("ERROR: Could not create a temporary file!");
			}
			
			GMSerializer.of(type)
						.serialize(metric)			
						.toFile(tmp);
			
			return tmp;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
