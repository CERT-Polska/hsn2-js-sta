/*
 * Copyright (c) NASK, NCSC
 * 
 * This file is part of HoneySpider Network 2.0.
 * 
 * This is a free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package pl.nask.hsn2.service;

import java.lang.Thread.UncaughtExceptionHandler;

import org.apache.commons.daemon.Daemon;
import org.apache.commons.daemon.DaemonContext;
import org.apache.commons.daemon.DaemonController;
import org.apache.commons.daemon.DaemonInitException;

import pl.nask.hsn2.GenericService;
import pl.nask.hsn2.service.analysis.NGramsCalc;

public final class JsAnalyzerService implements Daemon {
	private Thread serviceRunner;
	private JsCommandLineParams cmd;

	public static void main(String[] args) throws DaemonInitException, InterruptedException {
		JsAnalyzerService jss = new JsAnalyzerService();
		jss.init(new JsvcArgsWrapper(args));
		jss.start();
		jss.serviceRunner.join();
		jss.stop();
		jss.destroy();
	}

	private static JsCommandLineParams parseArguments(String[] args) {
		JsCommandLineParams params = new JsCommandLineParams();
		params.parseParams(args);

		return params;
	}

	@Override
	public void init(DaemonContext context) throws DaemonInitException {
		cmd = parseArguments(context.getArguments());

		NGramsCalc.initialize(cmd.getLibPath());

	}

	@Override
	public void start() {
		final GenericService service = new GenericService(new JsAnalyzerTaskFactory(cmd), cmd.getMaxThreads(),
				cmd.getRbtCommonExchangeName(), cmd.getRbtNotifyExchangeName());
		cmd.applyArguments(service);
		serviceRunner = new Thread(new Runnable() {

			@Override
			public void run() {
				try {
					Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {

						@Override
						public void uncaughtException(Thread t, Throwable e) {
							System.exit(1);

						}
					});
					service.run();
				} catch (InterruptedException e) {
					System.exit(0);
				}

			}
		}, "Js-Sta-service");
		serviceRunner.start();

	}

	@Override
	public void stop() throws InterruptedException {
		serviceRunner.interrupt();
		serviceRunner.join();

	}

	@Override
	public void destroy() {

	}

	private static final class JsvcArgsWrapper implements DaemonContext {
		private String[] args;

		private JsvcArgsWrapper(String[] a) {
			this.args = a.clone();
		}

		@Override
		public DaemonController getController() {
			return null;
		}

		@Override
		public String[] getArguments() {
			return args;
		}
	}
}
