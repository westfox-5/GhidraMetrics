package it.unive.ghidra.metrics.base.interfaces;

import javax.swing.JComponent;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMWindowManager {

	GhidraMetricsPlugin getPlugin();
	
	JComponent getComponent();

	void onInitializationCompleted();

	void refresh();

	void revalidate();
}
