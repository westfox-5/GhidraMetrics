package it.unive.ghidra.metrics.base.interfaces;

import javax.swing.JComponent;

public interface GMiWindowManager {

	JComponent getComponent();
	
	void onInitializationCompleted();

	void refresh();

	void revalidate();
}
