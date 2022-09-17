package it.unive.ghidra.metrics.base.interfaces;

import javax.swing.JComponent;

public interface GMiWinManager {
	
	void init();
	JComponent getComponent();
		
	default void refresh() {
		getComponent().repaint();
	}
	
	default void revalidate() {
		getComponent().revalidate();
	}
}
