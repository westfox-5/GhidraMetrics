package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;

import docking.action.DockingAction;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricManagerGUI;
import it.unive.ghidra.metrics.gui.GMActionBack;
import it.unive.ghidra.metrics.gui.GMActionExport;
import it.unive.ghidra.metrics.gui.GMWindowManager;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

	private final GhidraMetricsPlugin plugin;
	private final GMWindowManager windowManager;

	private GMMetricManagerGUI metricManager;

	private List<DockingAction> localActions;

	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		this.windowManager = new GMWindowManager(plugin);
		
		createLocalActions();
		buildPanel();
	}

	private void buildPanel() {
		windowManager.init();

		showMainWindow();

		setVisible(true);
	}

	private void createLocalActions() {
		localActions = new ArrayList<>();

		localActions.add(new GMActionBack(plugin));

		for (GMMetricExporter.Type type : GMMetricExporter.Type.values()) {
			localActions.add(new GMActionExport(plugin, type));
		}
	}

	@Override
	public JComponent getComponent() {
		return windowManager.getComponent();
	}

	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}
	
	private final void updateWindow() {
		if ( metricManager != null ) {
			setSubTitle(metricManager.getMetric().getName());
			addAllLocalActions();
		} else {
			setSubTitle(null);
			removeAllLocalActions();
		}
		
		windowManager.updateWindow(metricManager);
	}

	public void showMainWindow() {
		metricManager = null;
		updateWindow();
	}

	public void showMetricWindow(String metricName) {
		metricManager = GhidraMetricsFactory.create(metricName, getPlugin());
		updateWindow();
	}

	public void doExport(GMMetricExporter.Type exportType) {
		if (metricManager == null)
			throw new RuntimeException("ERROR: no metric is selected!");

		try {
			GMBaseMetricExporter exporter = metricManager.makeExporter(exportType).withFileChooser().build();
			if ( exporter == null ) {
				return; // no error
			}
			
			Path exportPath = exporter.export();
			if (exportPath == null) {
				throw new RuntimeException("Could not export selected metric.");
			}

			Msg.info(this, "Export to file: " + exportPath.toAbsolutePath());
			Msg.showInfo(this, getComponent(), "Export", "File exported: " + exportPath.toAbsolutePath());

		} catch (IOException e) {
			metricManager.printException(e);
		}
	}

	public final void addAllLocalActions() {
		localActions.forEach(action -> addLocalAction(action));
	}
	
	public final void removeAllLocalActions() {
		localActions.forEach(action -> removeLocalAction(action));
	}
	
	public void locationChanged(ProgramLocation loc) {
		if ( metricManager == null || loc == null || !isVisible() ) {
			return;
		}
		
		Function fn = plugin.getCurrentProgram().getFunctionManager().getFunctionContaining(loc.getAddress());
		if ( fn != null ) {
			metricManager.functionChanged(fn);
		}
	}
}