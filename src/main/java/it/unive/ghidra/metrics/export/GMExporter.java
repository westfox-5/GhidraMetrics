package it.unive.ghidra.metrics.export;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.export.impl.GMExporterJSON;
import it.unive.ghidra.metrics.util.StringUtils;

public abstract class GMExporter {
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
	
	public static final GMExporter.Builder of(GMExporter.Type exportType) {
		return of(exportType, null);
	}

	public static final GMExporter.Builder of(GMExporter.Type exportType, GhidraMetricsPlugin plugin) { 
		return new Builder(exportType, plugin); 
	}
	
	private static final GMExporter newInstance(GMExporter.Type exportType) {
		switch (exportType) {
		case JSON: return new GMExporterJSON();
		default: return null;
		}
	}
	
	
	private final GMExporter.Type exportType;
	
	protected GMExporter(GMExporter.Type exportType) {
		this.exportType = exportType;
	}
	
	protected abstract <V> StringBuilder serialize(Collection<GMetric> metrics);
	
	public void serializeToFile(Path path, Collection<GMetric> metrics) throws IOException {
		if (Files.notExists(path, LinkOption.NOFOLLOW_LINKS)) {
			Files.createDirectories(path.getParent());
			Files.createFile(path);
		}
		
		StringBuilder sb = serialize(metrics);
		Stream<String> lines = Pattern.compile(System.lineSeparator()).splitAsStream(sb);
		
		if (lines == null)
			return;
		
		lines
			.map(line -> line + System.lineSeparator())
			.forEachOrdered(line -> writeLineToFile(path, line));
	}

	private void writeLineToFile(final Path path, final String line) {
		try {
			Files.writeString(path, line, StandardOpenOption.APPEND);
	
		// TODO handle these exceptions more gracefully
		} catch (IOException x) {
			x.printStackTrace();
		}				
	}
		
	public GMExporter.Type getExportType() {
		return exportType;
	}

	public final static class Builder {
		private final GMExporter.Type exportType;
		private final GhidraMetricsPlugin plugin;
		
		private List<GMetric> metrics;
		
		private boolean withFileChooser;
		private Path choosenPath;
		
		private Builder(GMExporter.Type exportType, GhidraMetricsPlugin plugin) {
			this.exportType = exportType;
			this.plugin = plugin;
			metrics = new ArrayList<>();
		}
		
		public Builder addMetric(GMetric metric) {
			this.metrics.add(metric);
			return this;
		}
		
		public Builder withFileChooser() {
			// TODO hide this method if plugin is null
			this.withFileChooser = true;
			this.choosenPath = null;
			return this;
		}
		
		public Builder toPath(Path destinationPath) {
			this.choosenPath = destinationPath;
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
		
		
		private Path getExportPath() {
			if (withFileChooser) {
				final GhidraFileChooser fileChooser = createFileChooser();
				File selectedFile = fileChooser.getSelectedFile();
				
				if (selectedFile == null)
					return null;
				
				return selectedFile.toPath();
			}
			
			return choosenPath;
		}
		
		public Path export() throws IOException {
			if (metrics.isEmpty()) 
				return null;
			
			if (exportType == null)
				return null;
			
			Path exportPath = getExportPath();
			if (exportPath == null) 
				return null;
			
			newInstance(exportType).serializeToFile(exportPath, metrics);
			
			return exportPath;
		}
	}
}
