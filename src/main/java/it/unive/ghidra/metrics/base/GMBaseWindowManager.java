package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;

public abstract class GMBaseWindowManager{
	
	private final JComponent component;
	
	protected GMBaseWindowManager() {
		this.component = createComponent();
	}

	protected abstract JComponent createComponent();
	
	public JComponent getComponent() {
		return component;
	}

	public void refresh() {
		component.repaint();
	}
	
	public void revalidate() {
		component.revalidate(); // note: goes recursively on children!
	}
}
