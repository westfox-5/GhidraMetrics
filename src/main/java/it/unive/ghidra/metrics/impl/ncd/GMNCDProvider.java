package it.unive.ghidra.metrics.impl.ncd;

import java.io.File;
import java.io.IOException;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;

public class GMNCDProvider extends GMBaseMetricProvider<GMNCD, GMNCDProvider, GMNCDWinManager> {

	public GMNCDProvider(Program program) {
		super(program, GMNCD.class);
	}

	public GMNCDProvider(GhidraMetricsPlugin plugin) {
		super(plugin, GMNCD.class, GMNCDWinManager.class);
	}
	
	
	public void fileSelected() {
		if (getWinManager().hasSelectedFiles()) {
			List<File> selectedFiles = getWinManager().getSelectedFiles();
			
			try {
				getMetric().init(selectedFiles);
			
			// TODO handle these exceptions more gracefully
			} catch(IOException x) {
				x.printStackTrace();
			}
			
			getWinManager().setNcdVisible(true);
		} else {
			getWinManager().setNcdVisible(false);
		}
	}
	

}
