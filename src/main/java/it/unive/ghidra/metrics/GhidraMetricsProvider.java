package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
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
import it.unive.ghidra.metrics.base.GMBaseMetricWinManager;
import it.unive.ghidra.metrics.export.GMExporter;
import it.unive.ghidra.metrics.ui.GMActionBack;
import it.unive.ghidra.metrics.ui.GMActionExport;
import it.unive.ghidra.metrics.ui.GMWindowManager;

public class GhidraMetricsProvider extends ComponentProvider {
	
	private final GhidraMetricsPlugin plugin;
	private final GMWindowManager wManager;
	private final GMActiveProvider<?,?,?> activeProvider;

	private List<DockingAction> actions;
	
	
	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		
		this.wManager = new GMWindowManager(plugin);
		
		this.activeProvider = new GMActiveProvider<>();
				
		buildPanel();
		createActions();
	}

	private void buildPanel() {
		// nothing to do 
		
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
	
	
	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}

	public void showMainWindow() {
		activeProvider.reset();
		refresh();
	}
	
	public void showMetric(Class<? extends GMBaseMetric<?, ?, ?>> metricClz) {
		activeProvider.changeTo(metricClz);
		refresh();
	}
	
	public void doExport(GMExporter.Type exportType) {
		if (!activeProvider.has()) 
			throw new RuntimeException("ERROR: No active provider is selected!");

		GMExporter exporter = activeProvider.get().makeExporter(exportType).build();
		
		try {
			Path exportPath = exporter.export();
			
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
		
		if (activeProvider.has()) {
			// metric view
			setSubTitle(activeProvider.get().getMetric().getName());
			addLocalActions();
			
		} else {
			// main view
			setSubTitle(null);
			removeLocalActions();
		}

		wManager.showView(activeProvider.get()); // null will show main view
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
	
	private final class GMActiveProvider
		<M extends GMBaseMetric<M, P, W>, 
		P extends GMBaseMetricProvider<M, P, W>,
		W extends GMBaseMetricWinManager<M, P, W>> {
		
		private final Map<Class<? extends GMBaseMetric<?,?,?>>, GMBaseMetricProvider<?,?,?>> _cache = new HashMap<>();
		private P provider;
		
		@SuppressWarnings("unchecked")
		public void changeTo(Class<? extends GMBaseMetric<?, ?, ?>> clz) {
			provider = (P) _cache.get(clz);
			if (provider == null) {
				provider = GMBaseMetricProvider.GMMetricProviderFactory.create(getPlugin(), (Class<M>) clz);
				_cache.put(clz, provider);
			}
		}

		public void reset() {
			this.provider = null;
		}
		
		public boolean has() {
			return provider != null;
		}
		
		public P get() {
			return provider;
		}
	}

	public void locationChanged(ProgramLocation loc) {
		if (!activeProvider.has())
			return;
		
		if (loc == null) 
			return;
		
		if (!isVisible())
			return;
		
		activeProvider.get().locationChanged(loc);
	}
}