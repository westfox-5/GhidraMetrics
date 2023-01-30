package it.unive.ghidra.metrics.base.interfaces;

import javax.swing.JComponent;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMWindow {

	GhidraMetricsPlugin getPlugin();

	JComponent getComponent();

	default void refresh() { 
		Swing.runIfSwingOrRunLater( () -> {
			getComponent().revalidate();
			getComponent().repaint();
		});
	}
}
