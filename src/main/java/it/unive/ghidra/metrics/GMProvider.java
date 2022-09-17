package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JComponent;

import docking.ComponentProvider;
import docking.action.DockingAction;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMBaseMetricProvider;
import it.unive.ghidra.metrics.base.GMBaseMetric;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.ui.GMActionBack;
import it.unive.ghidra.metrics.ui.GMActionExport;
import it.unive.ghidra.metrics.ui.GMWindowManager;

public class GMProvider extends ComponentProvider {
	
	private final GhidraMetricsPlugin plugin;
	private final GMWindowManager wManager;
	private final GMProvidersCache providersCache;	// caches instances of metric providers

	private GMBaseMetricProvider<? extends GMBaseMetric> activeProvider;
	private List<DockingAction> actions;
	

	public GMProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		this.wManager = new GMWindowManager(plugin);
		
		this.providersCache = new GMProvidersCache();
		
		buildPanel();
		createActions();
	}

	private void buildPanel() {
		Collection<Class<? extends GMBaseMetric>> enabledMetrics = GhidraMetricsPlugin.DEBUG ? GMBaseMetric.allMetrics():  GhidraMetricsPlugin.getEnabledMetrics();
		wManager.addEnabledMetrics(enabledMetrics);
		
		setVisible(true);
	}

	private void createActions() {
		this.actions = new ArrayList<>();
		
		actions.add(new GMActionBack(plugin));
		
		for (GMExporter.Type type: GMExporter.Type.values()) {
			actions.add(new GMActionExport(plugin, type));
		}
	}

	@Override
	public JComponent getComponent() {
		return wManager.getComponent();
	}
	
	public GMBaseMetricProvider<?> getActiveProvider() {
		return activeProvider;
	}
	
	public void showMainWindow() {
		this.activeProvider = null;
		wManager.show(null);
		refresh();
	}
	
	public <W extends GMBaseMetric> void showMetric(Class<W> metricClz) {
		this.activeProvider = providersCache.get(metricClz);
		
		wManager.show(activeProvider);
		refresh();
	}
	
	public void doExport(GMExporter.Type exportType) {
		if (activeProvider == null) 
			throw new RuntimeException("ERROR: No active provider is selected!");

		GMBaseMetric metric = activeProvider.getMetric();

		try {
			Path exportPath = GMExporter.of(exportType, plugin).addMetric(metric).withFileChooser().export();
			
			if (exportPath == null)
				throw new RuntimeException("Could not export selected metric.");
			
			Msg.info(this, "Export to file: "+ exportPath.toAbsolutePath());
			Msg.showInfo(this, getComponent(), "Export", "File exported: "+ exportPath.toAbsolutePath());
			
		// TODO handle these exceptions more gracefully
		} catch (IOException x) {
			x.printStackTrace();
		}
	}
	
	public final void refresh() {
		if (activeProvider == null) {
			// main view
			setSubTitle(null);
			removeLocalActions();
			
		} else {
			// metric view
			setSubTitle(activeProvider.getMetric().getName());
			addLocalActions();
		}

		wManager.refresh();
	}
	
	private final void addLocalActions() {
		for (DockingAction action: actions) {
			dockingTool.addLocalAction(this, action);
		}
	}
	
	private final void removeLocalActions() {
		for (DockingAction action: actions) {
			dockingTool.removeLocalAction(this, action);
		}
	}
	

	private final class GMProvidersCache {
		private final Map<Class<? extends GMBaseMetric>, GMBaseMetricProvider<?>> _cache;
		
		public GMProvidersCache(){
			this._cache = new HashMap<>();	
		}
		
		@SuppressWarnings("unchecked")
		public <W extends GMBaseMetric> GMBaseMetricProvider<W> get(Class<W> clz) {
			GMBaseMetricProvider<W> provider = (GMBaseMetricProvider<W>) _cache.get(clz);
			if (provider == null) {
				provider = new GMBaseMetricProvider<W>(plugin, clz);
				_cache.put(clz, provider);
			}
			return provider;
		}
	}

	public void locationChanged(ProgramLocation loc) {
		if (activeProvider == null)
			return;
		
		if (loc == null) 
			return;
		
		if (!isVisible())
			return;
		
		activeProvider.locationChanged(loc);
	}
}