package it.unive.ghidra.metrics.impl.similarity;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import ghidra.app.util.exporter.ExporterException;
import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricController;
import it.unive.ghidra.metrics.base.interfaces.GMZipper;
import it.unive.ghidra.metrics.impl.GhidraMetricsFactory;
import it.unive.ghidra.metrics.util.ZipHelper.ZipException;

public class GMSimilarityController extends GMBaseMetricController<GMSimilarity, GMSimilarityController, GMSimilarityWindow> {

	private List<Path> selectedFiles;
	private GMZipper zipper;
	
	public GMSimilarityController(Program program) {
		super(program, GMSimilarity.class);
	}

	public GMSimilarityController(GhidraMetricsPlugin plugin) {
		super(plugin, GMSimilarity.class, GMSimilarityWindow.class);
	}
	
	@Override
	protected void init() {	
		zipper = GhidraMetricsFactory.getZipper(GhidraMetricsFactory.allZippers().iterator().next());
	}	

	public List<Path> getSelectedFiles() {
		return selectedFiles;
	}

	public void setSelectedFiles(List<Path> selectedFiles) {
		this.selectedFiles = selectedFiles;
	}
	
	public boolean hasSelectedFiles() {
		return selectedFiles != null && !selectedFiles.isEmpty();
	}

	public void compute() {
		getMetric().clearMeasures();
		
		if (hasSelectedFiles()) {
			try {
				getMetric().createMeasures(selectedFiles);
			} catch (ZipException | ExporterException | IOException e) {
				printException(e);
			}			
		}

		if (guiEnabled) {
			getWindow().refresh();
		}
	}

	public GMZipper getZipper() {
		return zipper;
	}

	public void setZipper(GMZipper zipper) {
		this.zipper = zipper;
	}
}
