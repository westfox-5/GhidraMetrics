package it.unive.ghidra.metrics.impl.similarity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.listing.Program;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMBaseMetricManager;

public class GMSimilarityManager extends GMBaseMetricManager<GMSimilarity, GMSimilarityManager, GMSimilarityWinManager> {

	private List<Path> selectedFiles;
	
	public GMSimilarityManager(Program program) {
		super(program, GMSimilarity.class);
	}

	public GMSimilarityManager(GhidraMetricsPlugin plugin) {
		super(plugin, GMSimilarity.class, GMSimilarityWinManager.class);
	}
	
	@Override
	protected void init() {
		this.selectedFiles = new ArrayList<>();
	}	

	public void fileSelected() {
		
		if (getWinManager().hasSelectedFiles()) {
			List<Path> toCompute = getWinManager().getSelectedFiles();
			this.selectedFiles.addAll(toCompute);
			
			try {	
				getMetric().createMetricValues(toCompute);
			} catch (Exception e) {
				printException(e);
			}
		} 
		
		getWinManager().revalidate();
		getWinManager().refresh();
	}
	
	public void clearSelectedFiles() {
		this.selectedFiles.clear();
		getMetric().clearMeasures();
		
		getWinManager().revalidate();
		getWinManager().refresh();
	}

}