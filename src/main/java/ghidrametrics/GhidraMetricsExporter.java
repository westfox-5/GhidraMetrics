package ghidrametrics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import ghidrametrics.base.BaseMetricWrapper;
import ghidrametrics.serialize.Serializer;

public class GhidraMetricsExporter {
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
	
	public static final GhidraMetricsExporter of(GhidraMetricsExporter.Type type) { 
		return new GhidraMetricsExporter(type); 
	}
	
	
	private final GhidraMetricsExporter.Type type;
	
	private GhidraMetricsExporter(GhidraMetricsExporter.Type type) {
		this.type = type;
	}
	
	public Path export(BaseMetricWrapper wrapper) {
		if (wrapper == null) {
			throw new RuntimeException("ERROR: No wrapper to export!");
		}
		
		try {
			Path tmp = newTemp();			
			if (Files.notExists(tmp)) {
				throw new RuntimeException("ERROR: Could not create a temporary file!");
			}
			
			Serializer.of(type)
						.serialize(wrapper)			
						.toFile(tmp);
			
			return tmp;
			
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}
}
