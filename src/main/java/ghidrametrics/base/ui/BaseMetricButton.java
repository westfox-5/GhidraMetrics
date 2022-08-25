package ghidrametrics.base.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;

import ghidrametrics.GhidraMetricsProvider;

public class BaseMetricButton extends JButton implements ActionListener {
	private static final long serialVersionUID = 1L;
	
	private final GhidraMetricsProvider originalProvider;
	private final BaseMetricProvider<?> mProvider;
	
	public BaseMetricButton(BaseMetricProvider<?> mProvider, GhidraMetricsProvider originalProvider) {
		super(mProvider.getName());
		this.mProvider = mProvider;
		this.originalProvider = originalProvider;
		
		setActionCommand(mProvider.getName());
		addActionListener(this);
	}
	
	@Override
	public void actionPerformed(ActionEvent ae) {
		String actionCommand = ae.getActionCommand();
		if (actionCommand.equals(mProvider.getName())) {
			mProvider.init();	
			originalProvider.showMetricView(mProvider);
			originalProvider.setVisible(true);
		}
	}

}
