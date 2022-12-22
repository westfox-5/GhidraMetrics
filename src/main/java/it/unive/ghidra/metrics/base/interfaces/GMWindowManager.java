package it.unive.ghidra.metrics.base.interfaces;

import javax.swing.JComponent;

import ghidra.util.Swing;
import it.unive.ghidra.metrics.GhidraMetricsPlugin;

public interface GMWindowManager {

	GhidraMetricsPlugin getPlugin();

	JComponent getComponent();

	default void repaint() { 
		Swing.runIfSwingOrRunLater( () -> getComponent().repaint() );
	}

	default void revalidate() { 
		Swing.runIfSwingOrRunLater( () -> getComponent().revalidate() );
	}
}
