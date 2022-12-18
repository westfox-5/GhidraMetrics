package it.unive.ghidra.metrics.base.interfaces;

import java.io.IOException;
import java.nio.file.Path;

public interface GMMetricExporter {

	public static enum Type {
		JSON("json", "application/json"),
		TXT("txt", "text/plain");
	
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

	Path export() throws IOException;
	
	GMMetricExporter.Type getExportType();
}
