package it.unive.ghidra.metrics.impl.ncd;

import java.io.File;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMAbstractMetricManager;
import it.unive.ghidra.metrics.util.ZipHelper.ZipException;

public class GMNCDManager extends GMAbstractMetricManager<GMNCD, GMNCDManager, GMNCDWinManager> {

	public GMNCDManager(Program program) {
		super(program, GMNCD.class);
	}

	public GMNCDManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMNCD.class, GMNCDWinManager.class);
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
