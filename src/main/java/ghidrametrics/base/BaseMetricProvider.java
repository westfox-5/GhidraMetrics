package ghidrametrics.base;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ghidra.program.model.listing.Program;
import ghidrametrics.GhidraMetricsPlugin;

public abstract class BaseMetricProvider<T extends BaseMetricWrapper> {

	private final Class<T> wrapperClz;
	protected final GhidraMetricsPlugin plugin;
	protected T wrapper;
	protected JPanel panel;

	public BaseMetricProvider(GhidraMetricsPlugin plugin, Class<T> wrapperClz) {
		this.plugin = plugin;
		this.wrapperClz = wrapperClz;
	}

	public final T getWrapper() {
		return wrapper;
	}

	public Class<T> getWrapperClz() {
		return wrapperClz;
	}

	protected abstract void initWrapper(T wrapper);
	protected abstract void buildComponent();
	
	public final void init() {
		if (wrapper == null) {
			
			try {
				Constructor<T> declaredConstructor = wrapperClz.getDeclaredConstructor(Program.class);
				wrapper = declaredConstructor.newInstance(getCurrentProgram());
				
				initWrapper(wrapper);

			// TODO handle these exceptions more gracefully
			} catch (InstantiationException x) {
			    x.printStackTrace();
			} catch (IllegalAccessException x) {
			    x.printStackTrace();
			} catch (InvocationTargetException x) {
			    x.printStackTrace();
			} catch (NoSuchMethodException x) {
			    x.printStackTrace();
			}
			
			buildComponent();
		}
	}

	public final Program getCurrentProgram() {
		return plugin.getCurrentProgram();
	}

	public final JComponent getComponent() {
		return panel;
	}
	
}