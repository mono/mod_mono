/*
 * ApacheApplicationHost.cs
 * 
 * Authors:
 * 	Daniel Lopez Ridruejo
 * 	Gonzalo Paniagua Javier
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo
 *           (c) 2002 Novell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Web.Hosting;
using Mono.ASPNET;

namespace Apache.Web
{
	public class ApacheApplicationHost : MarshalByRefObject, IApplicationHost
	{
		object IApplicationHost.CreateApplicationHost (string virtualPath, string baseDirectory)
		{
			return CreateApplicationHost (virtualPath, baseDirectory);
		}

		public static object CreateApplicationHost (string virtualPath, string baseDirectory)
		{
			return ApplicationHost.CreateApplicationHost (typeof (ApacheApplicationHost), virtualPath, baseDirectory);
		}

		/* Hack until fix for TP calls from C, that did not made it in Mono 0.20 */
		private void internalProcessRequest (IntPtr request) {
			ApacheWorkerRequest wr = new ApacheWorkerRequest (this, request);
			wr.ProcessRequest ();
		}

		public void ProcessRequest (IntPtr request)
		{
			internalProcessRequest(request);
		}
		
		public string Path
		{
			get {
				return AppDomain.CurrentDomain.GetData (".appPath").ToString ();
			}
		}

		public string VPath
		{
			get {
				return AppDomain.CurrentDomain.GetData (".appVPath").ToString ();
			}
		}

	}
}

