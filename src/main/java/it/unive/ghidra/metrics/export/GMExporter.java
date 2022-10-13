package it.unive.ghidra.metrics.export;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMiMetric;
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
		case JSON:
			return new GMExporterJSON();
		default:
			return null;
		}
	}

	private final GMExporter.Type exportType;
	private List<GMiMetric> metrics;
	private Path exportPath;

	protected GMExporter(GMExporter.Type exportType) {
		this.exportType = exportType;
	}

	protected abstract <V> StringBuilder serialize(Collection<GMiMetric> metrics);

	public Path export() throws IOException {

		if (!accept(exportPath, exportType))
			throw new IOException("Only " + exportType.name() + " Files ( *." + exportType.getExtension() + ")");

		Files.deleteIfExists(exportPath);
		Files.createDirectories(exportPath.getParent());
		Files.createFile(exportPath);

		StringBuilder sb = serialize(metrics);
		Stream<String> lines = Pattern.compile(System.lineSeparator()).splitAsStream(sb);

		if (lines != null) {
			lines.map(line -> line + System.lineSeparator()).forEachOrdered(line -> writeLineToFile(exportPath, line));
		}

		return exportPath;
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

		private List<GMiMetric> metrics;

		private boolean withFileChooser;
		private Path choosenPath;

		private Builder(GMExporter.Type exportType, GhidraMetricsPlugin plugin) {
			this.exportType = exportType;
			this.plugin = plugin;
			metrics = new ArrayList<>();
		}

		public Builder addMetric(GMiMetric metric) {
			this.metrics.add(metric);
			return this;
		}

		public Builder addMetrics(Collection<? extends GMiMetric> metrics) {
			this.metrics.addAll(metrics);
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
			GhidraFileFilter fileFilter = new GhidraFileFilter() {
				@Override
				public String getDescription() {
					return exportType.name() + " Files ( *." + exportType.getExtension() + ")";
				}

				@Override
				public boolean accept(File arg0, GhidraFileChooserModel arg1) {
					String extension = StringUtils.getFileExtension(arg0);
					return exportType.getExtension().equalsIgnoreCase(extension);
				}
			};

			GhidraFileChooser fileChooser = new GhidraFileChooser(plugin.getProvider().getComponent());
			fileChooser.setMultiSelectionEnabled(false);
			fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			fileChooser.setSelectedFileFilter(fileFilter); // doesn't seems to work..

			return fileChooser;
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

		public GMExporter build() {
			if (metrics.isEmpty())
				return null;

			if (exportType == null)
				return null;

			Path exportPath = getExportPath();
			if (exportPath == null)
				return null;

			GMExporter exporter = newInstance(exportType);
			exporter.exportPath = exportPath;
			exporter.metrics = metrics;

			return exporter;
		}
	}

	private static boolean accept(Path path, GMExporter.Type exportType) {
		String extension = StringUtils.getFileExtension(path.toFile());
		return exportType.getExtension().equalsIgnoreCase(extension);
	}
}
