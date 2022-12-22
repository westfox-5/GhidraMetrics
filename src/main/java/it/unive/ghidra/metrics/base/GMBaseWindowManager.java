package it.unive.ghidra.metrics.base;

import javax.swing.JComponent;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.interfaces.GMWindowManager;

public abstract class GMBaseWindowManager implements GMWindowManager {

	private final GhidraMetricsPlugin plugin;
	private final JComponent component;

	protected abstract boolean init();
	protected abstract JComponent createComponent();
	
	protected GMBaseWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
		this.component = createComponent();
	}

	@Override
	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}
}
