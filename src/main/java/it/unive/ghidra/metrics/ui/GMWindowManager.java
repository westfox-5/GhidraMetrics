package it.unive.ghidra.metrics.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.Collection;

import javax.swing.BoxLayout;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import it.unive.ghidra.metrics.GhidraMetricsPlugin;
import it.unive.ghidra.metrics.base.GMetric;
import it.unive.ghidra.metrics.base.GMBaseProvider;

public class GMWindowManager {
	
	private final GhidraMetricsPlugin plugin;
	
	private final JPanel 
			container, // Main window
			pnlMetricList, // Metrics buttons container
			pnlMetricContainer // Metric content
	;
	
	private final JLabel 
		lblMetricName
	;
	
	/**
	 * Create the frame.
	 */
	public GMWindowManager(GhidraMetricsPlugin plugin) {
		this.plugin = plugin;
		
		container = new JPanel();
		container.setBorder(new EmptyBorder(5, 5, 5, 5));

		container.setLayout(new BorderLayout(0, 0));
		
		pnlMetricContainer = new JPanel();
		pnlMetricContainer.setVisible(false);
		pnlMetricContainer.setMaximumSize(new Dimension(32767, 30));
		container.add(pnlMetricContainer, BorderLayout.NORTH);
		pnlMetricContainer.setLayout(new BorderLayout(0, 0));
		
		JPanel pnlMetricHeader = new JPanel();
		pnlMetricContainer.add(pnlMetricHeader, BorderLayout.NORTH);
		pnlMetricHeader.setMaximumSize(new Dimension(32767, 30));
		pnlMetricHeader.setLayout(new BoxLayout(pnlMetricHeader, BoxLayout.X_AXIS));
		
		JPanel pnlMetricFooter= new JPanel();
		pnlMetricContainer.add(pnlMetricFooter, BorderLayout.SOUTH);
		
		lblMetricName = new JLabel();
		pnlMetricHeader.add(lblMetricName);
		lblMetricName.setHorizontalAlignment(SwingConstants.LEFT);
		
		pnlMetricList = new JPanel();
		container.add(pnlMetricList, BorderLayout.CENTER);
		pnlMetricList.setLayout(new GridLayout(0, 1, 0, 0));
		pnlMetricList.setVisible(true);
	}

	public JPanel getComponent() {
		return container;
	}

	public final void addEnabledMetrics(Collection<Class<? extends GMetric>> metricsClz) {
		for (Class<? extends GMetric> metricClz: metricsClz) {
			pnlMetricList.add(GMButton.of(plugin, metricClz));
		}
	}
	
	public final void show(GMBaseProvider<?> mProvider) {
		if (mProvider == null) {
			pnlMetricContainer.setVisible(false);
			pnlMetricList.setVisible(true);

		} else {
			lblMetricName.setText(mProvider.getMetric().getName());
			
			JComponent component = mProvider.getComponent();
			pnlMetricContainer.add(component, BorderLayout.CENTER); 

			pnlMetricList.setVisible(false);
			pnlMetricContainer.setVisible(true);			
		}
		
		container.revalidate(); // note: goes recursively on children!
	}

	public final void refresh() {
		container.repaint();
	}
}
