package ghidrametrics.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import ghidrametrics.GhidraMetricsProvider;
import ghidrametrics.GhidraMetricsPlugin;
import ghidrametrics.base.BaseMetricProvider;

public class GhidraMetricsWrapperButton extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;
	
	public static final GhidraMetricsWrapperButton of(GhidraMetricsPlugin plugin, BaseMetricProvider<?> mProvider) {
		return new GhidraMetricsWrapperButton(plugin, mProvider);
	}
	
	private final String title;
	
	private final GhidraMetricsPlugin plugin;
	private final BaseMetricProvider<?> mProvider;
	
	private GhidraMetricsWrapperButton(GhidraMetricsPlugin plugin, BaseMetricProvider<?> mProvider) {
		super();
		this.plugin = plugin;
		this.mProvider = mProvider;
		this.title = mProvider.getWrapperClz().getSimpleName().replace("Wrapper", "");
		
		setText(title);
		setActionCommand(title);
		addActionListener(this);
	}
	
	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(title)) {
			GhidraMetricsProvider provider = plugin.getProvider();
			
			provider.showView(mProvider);
		}
	}

}
