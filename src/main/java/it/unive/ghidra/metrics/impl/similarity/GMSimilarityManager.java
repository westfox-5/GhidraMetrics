package it.unive.ghidra.metrics.impl.similarity;

import java.io.File;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricManager;
import it.unive.ghidra.metrics.util.ZipHelper.ZipException;

public class GMSimilarityManager extends GMBaseMetricManager<GMSimilarity, GMSimilarityManager, GMSimilarityWinManager> {

	public GMSimilarityManager(Program program) {
		super(program, GMSimilarity.class);
	}

	public GMSimilarityManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMSimilarity.class, GMSimilarityWinManager.class);
	}

	public void fileSelected() {
		if (getWinManager().hasSelectedFiles()) {
			List<File> selectedFiles = getWinManager().getSelectedFiles();

			try {
				getMetric().compute(selectedFiles);
			} catch (ZipException e) {
				printException(e);
			}

			getWinManager().setNcdVisible(true);
		} else {
			getWinManager().setNcdVisible(false);
		}
	}

}
