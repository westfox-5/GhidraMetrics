package it.unive.ghidra.metrics;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.serialize.GMSerializer;
import it.unive.ghidra.metrics.util.StringUtils;

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
	
	public static final GMExporter.Builder make(GhidraMetricsPlugin plugin) { 
		return new Builder(plugin); 
	}
	
	
	public final static class Builder {
		private final GhidraMetricsPlugin plugin;
		
		private Type exportType;
		private List<GMetric> metrics;
		
		private boolean withFileChooser;
		private Path path;
		
		private Builder(GhidraMetricsPlugin plugin) {
			this.plugin = plugin;
			metrics = new ArrayList<>();
		}
		
		public Builder addMetric(GMetric metric) {
			this.metrics.add(metric);
			return this;
		}
		
		public Builder exportType(Type exportType) {
			this.exportType = exportType;
			return this;
		}
		
		public Builder withFileChooser() {
			this.withFileChooser = true;
			this.path = null;
			return this;
		}
		
		public Builder toPath(Path destinationPath) {
			this.path = destinationPath;
			this.withFileChooser = false;
			return this;
		}
		
		private GhidraFileChooser createFileChooser() {
			GhidraFileChooser fc = new GhidraFileChooser( plugin.getProvider().getComponent() );
			fc.setMultiSelectionEnabled(false);
			fc.setSelectedFileFilter(new GhidraFileFilter() {
				@Override
				public String getDescription() {
					return "Only " + exportType.name() + " files";
				}
				
				@Override
				public boolean accept(File arg0, GhidraFileChooserModel arg1) {					
					String extension = StringUtils.getFileExtension(arg0);
					return exportType.getExtension().equalsIgnoreCase(extension);
				}
			});
			
			return fc;
		}
		
		public Path export() throws IOException {
			if (metrics.isEmpty()) 
				return null;
			
			if (exportType == null)
				return null;
			
			Path destPath;
			if (withFileChooser) {
				final GhidraFileChooser fileChooser = createFileChooser();
				destPath = fileChooser.getSelectedFile().toPath();
			} else {
				destPath = path;
			}
			
			GMSerializer serializer = GMSerializer.of(exportType);
			serializer.serializeAll(metrics);
			serializer.toFile(path);
			
			return destPath;
		}
	}
}
