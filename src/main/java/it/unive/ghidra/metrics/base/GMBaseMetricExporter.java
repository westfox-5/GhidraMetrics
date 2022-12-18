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
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManager;
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

	private static final GMBaseMetricExporter create(GMMetricManager manager, GMMetricExporter.Type exportType) {
		switch (exportType) {
		case JSON:
			return new GMExporterJSON(manager);
		case TXT:
			return new GMExporterTXT(manager);
		default:
			throw new IllegalArgumentException("Export type " + exportType.name() + " is not implemented");
		}
	}

	
	private final GMMetricExporter.Type exportType;
	private final GMMetricManager manager;
	private Path exportPath;

	protected GMBaseMetricExporter(GMMetricManager manager, GMMetricExporter.Type exportType) {
		this.manager = manager;
		this.exportType = exportType;
	}

	protected abstract <V> StringBuilder serialize(Collection<GMMetric> metrics);

	@Override
	public Path export() throws IOException {

		if (!accept(exportPath, exportType))
			throw new IOException("Only " + exportType.name() + " Files ( *." + exportType.getExtension() + ")");

		Files.deleteIfExists(exportPath);
		Files.createDirectories(exportPath.getParent());
		Files.createFile(exportPath);

		Collection<GMMetric> metrics = manager.getExportableMetrics();
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
			manager.printException(e);
		}
	}

	public GMMetricExporter.Type getExportType() {
		return exportType;
	}
	
	public static final GMBaseMetricExporter.Builder make(GMMetricExporter.Type exportType, GMMetricManager manager) {
		return new Builder(exportType, manager);
	}

	public final static class Builder {
		private final GMMetricExporter.Type exportType;
		private final GMMetricManager manager;

		private List<GMMetric> metrics;

		private boolean withFileChooser;
		private Path choosenPath;

		private Builder(GMMetricExporter.Type exportType, GMMetricManager manager) {
			this.exportType = exportType;
			this.manager = manager;
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
			if ( manager instanceof GMMetricManagerGUI ) {
				GhidraFileChooser fileChooser = new GhidraFileChooser(((GMMetricManagerGUI) manager).getPlugin().getProvider().getComponent());
				fileChooser.setMultiSelectionEnabled(false);
				fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
				fileChooser.setFileFilter(new ExtensionFileFilter(
						new String[] { exportType.getExtension() }, exportType.getContentType()));
				fileChooser.setApproveButtonText("Export");
				File newFile = new File(USER_HOME, "gm-export-"+(new SimpleDateFormat("ddMMyyy-HHmmsss").format(new Date()))+"."+exportType.getExtension());
				
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
			
			GMBaseMetricExporter exporter = GMBaseMetricExporter.create(manager, exportType);
			exporter.exportPath = exportPath;

			return exporter;
		}
	}

	private static boolean accept(Path path, GMMetricExporter.Type exportType) {
		String extension = StringUtils.getFileExtension(path.toFile());
		return exportType.getExtension().equalsIgnoreCase(extension);
	}
}
