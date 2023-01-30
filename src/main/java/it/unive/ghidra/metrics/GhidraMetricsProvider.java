package it.unive.ghidra.metrics;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;

import docking.action.DockingAction;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import it.unive.ghidra.metrics.base.GMBaseMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricExporter;
import it.unive.ghidra.metrics.base.interfaces.GMMetricControllerGUI;
import it.unive.ghidra.metrics.gui.GMActionBack;
import it.unive.ghidra.metrics.gui.GMActionExport;
import it.unive.ghidra.metrics.impl.GhidraMetricsFactory;

public class GhidraMetricsProvider extends ComponentProviderAdapter {

	private final GhidraMetricsPlugin plugin;
	private final GhidraMetricsWindow window;

	private GMMetricControllerGUI metricController;

	private List<DockingAction> localActions;

	public GhidraMetricsProvider(GhidraMetricsPlugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		this.plugin = plugin;
		this.window = new GhidraMetricsWindow(plugin);
		
		createLocalActions();
		buildPanel();
	}

	private void buildPanel() {
		window.init();

		showMainWindow();

		setVisible(true);
	}

	private void createLocalActions() {
		localActions = new ArrayList<>();

		localActions.add(new GMActionBack(plugin));
	}

	@Override
	public JComponent getComponent() {
		return window.getComponent();
	}

	public GhidraMetricsPlugin getPlugin() {
		return plugin;
	}
	
	private final void updateWindow() {
		if ( metricController != null ) {
			String metricName = metricController.getMetric().getName();
			setSubTitle(metricName);
			addAllLocalActions(metricName);
		} else {
			setSubTitle(null);
			removeAllLocalActions();
		}
		
		window.updateWindow(metricController);
	}

	public void showMainWindow() {
		metricController = null;
		updateWindow();
	}

	public void showMetricWindow(String metricName) {
		metricController = GhidraMetricsFactory.create(metricName, getPlugin());
		updateWindow();
	}

	public void doExport(GMMetricExporter.FileFormat fileFormat) {
		if (metricController == null)
			throw new RuntimeException("ERROR: no metric is selected!");

		try {
			GMBaseMetricExporter exporter = metricController.makeExporter(fileFormat).withFileChooser().build();
			if ( exporter == null ) {
				return; // no error
			}
			
			Path exportPath = exporter.export();
			if (exportPath == null) {
				throw new RuntimeException("Could not export selected metric.");
			}

			Msg.showInfo(this, getComponent(), "Export", "File exported: " + exportPath.toAbsolutePath());

		} catch (IOException e) {
			metricController.printException(e);
		}
	}

	public final void addAllLocalActions(String metricName) {
		for (GMMetricExporter.FileFormat fileFormat : GMMetricExporter.FileFormat.values()) {
			GMActionExport gmActionExport = new GMActionExport(plugin, metricName, fileFormat);
			localActions.add(gmActionExport);
		}

		localActions.forEach(action -> addLocalAction(action));
	}
	
	public final void removeAllLocalActions() {
		localActions.forEach(action -> removeLocalAction(action));

		createLocalActions();
	}
	
	public void locationChanged(ProgramLocation loc) {
		if ( metricController == null || loc == null || !isVisible() ) {
			return;
		}
		
		metricController.locationChanged(loc);
	}
}