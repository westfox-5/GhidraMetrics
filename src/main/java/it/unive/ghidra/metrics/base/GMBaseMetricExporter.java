package it.unive.ghidra.metrics.base;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.filechooser.ExtensionFileFilter;
import it.unive.ghidra.metrics.base.interfaces.GMMetric;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricController;
import it.unive.ghidra.metrics.export.GMExporterJSON;
import it.unive.ghidra.metrics.export.GMExporterTXT;
import it.unive.ghidra.metrics.util.StringUtils;

public abstract class GMBaseMetricExporter implements GMMetricExporter {
	
	private static final String USER_HOME;
	static {
		String userHome = null;
		if (System.getenv().containsKey("HOME")) {
			userHome = System.getenv("HOME");
		}
		USER_HOME = userHome;
	}

	private static final GMBaseMetricExporter create(GMMetricController controller, GMMetricExporter.FileFormat exportType) {
		switch (exportType) {
		case JSON:
			return new GMExporterJSON(controller);
		case TXT:
			return new GMExporterTXT(controller);
		default:
			throw new IllegalArgumentException("Export type " + exportType.name() + " is not implemented");
		}
	}

	
	private final GMMetricExporter.FileFormat fileFormat;
	private final GMMetricController controller;
	private Path exportPath;

	protected abstract <V> StringBuilder serialize(Collection<GMMetric> metrics);

	protected GMBaseMetricExporter(GMMetricController controller, GMMetricExporter.FileFormat fileFormat) {
		this.controller = controller;
		this.fileFormat = fileFormat;
	}

	@Override
	public Path export() throws IOException {

		if (!accept(exportPath, fileFormat))
			throw new IOException("Only " + fileFormat.name() + " Files ( *." + fileFormat.getExtension() + ")");

		Files.deleteIfExists(exportPath);
		Files.createDirectories(exportPath.getParent());
		Files.createFile(exportPath);

		Collection<GMMetric> metrics = controller.getExportableMetrics();
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

		} catch (IOException e) {
			controller.printException(e);
		}
	}

	public GMMetricExporter.FileFormat getFileFormat() {
		return fileFormat;
	}
	
	public static final GMBaseMetricExporter.Builder make(GMMetricExporter.FileFormat exportType, GMMetricController controller) {
		return new Builder(exportType, controller);
	}

	public final static class Builder {
		private final GMMetricExporter.FileFormat format;
		private final GMMetricController controller;

		private List<GMMetric> metrics;

		private boolean withFileChooser;
		private Path choosenPath;

		private Builder(GMMetricExporter.FileFormat fileFormat, GMMetricController controller) {
			this.format = fileFormat;
			this.controller = controller;
			metrics = new ArrayList<>();
		}

		public Builder addMetric(GMMetric metric) {
			this.metrics.add(metric);
			return this;
		}

		public Builder addMetrics(Collection<? extends GMMetric> metrics) {
			this.metrics.addAll(metrics);
			return this;
		}

		public Builder withFileChooser() {
			this.withFileChooser = true;
			this.choosenPath = null;
			return this;
		}

		public Builder toFile(Path path) {
			this.choosenPath = path;
			this.withFileChooser = false;
			return this;
		}

		private GhidraFileChooser createFileChooser() {
			if ( controller instanceof GMMetricControllerGUI ) {
				GhidraFileChooser fileChooser = new GhidraFileChooser(((GMMetricControllerGUI) controller).getPlugin().getProvider().getComponent());
				fileChooser.setMultiSelectionEnabled(false);
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				fileChooser.setFileFilter(new ExtensionFileFilter(
						new String[] { format.getExtension() }, format.getContentType()));
				fileChooser.setApproveButtonText("Export");
				File newFile = new File(USER_HOME, "gm-export-"+(new SimpleDateFormat("ddMMyyy-HHmmsss").format(new Date()))+"."+format.getExtension());
				
				fileChooser.setSelectedFile(newFile);
				return fileChooser;
			} 
			
			return null;
		}

		public GMBaseMetricExporter build() {
			Path exportPath = null;
			if (withFileChooser) {
				final GhidraFileChooser fileChooser = createFileChooser();
				File selectedFile = fileChooser.getSelectedFile();
				if (selectedFile != null) {
					exportPath = selectedFile.toPath();
				}
			} else {
				exportPath = choosenPath;
			}
			
			if ( exportPath == null ) { 
				return null;
			}
			
			GMBaseMetricExporter exporter = GMBaseMetricExporter.create(controller, format);
			exporter.exportPath = exportPath;

			return exporter;
		}
	}

	private static boolean accept(Path path, GMMetricExporter.FileFormat fileFormat) {
		String extension = StringUtils.getFileExtension(path.toFile());
		return fileFormat.getExtension().equalsIgnoreCase(extension);
	}
}
