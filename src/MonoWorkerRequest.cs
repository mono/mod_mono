/*
 * MonoWorkerRequest.cs
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
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Hosting;
using Math = System.Math;

namespace Mono.ASPNET
{
	public class MapPathEventArgs : EventArgs
	{
		string path;
		string mapped;
		bool isMapped;

		public MapPathEventArgs (string path)
		{
			this.path = path;
			isMapped = false;
		}

		public string Path {
			get { return path; }
		}
		
		public bool IsMapped {
			get { return isMapped; }
		}

		public string MappedPath {
			get { return mapped; }
			set {
				mapped = value;
				isMapped = (value != null && value != "");
			}
		}
	}

	public delegate void MapPathEventHandler (object sender, MapPathEventArgs args);
	
	public abstract class MonoWorkerRequest : SimpleWorkerRequest
	{
		IApplicationHost appHost;
		ArrayList response;
		Encoding encoding;
		string mappedPath;
		byte [] queryStringBytes;

		public MonoWorkerRequest (IApplicationHost appHost)
			: base (String.Empty, String.Empty, null)
		{
			if (appHost == null)
				throw new ArgumentNullException ("appHost");

			this.appHost = appHost;
			response = new ArrayList ();
		}

		public event MapPathEventHandler MapPathEvent;

		protected virtual Encoding Encoding {
			get {
				if (encoding == null)
					encoding = new UTF8Encoding (false);

				return encoding;
			}

			set { encoding = value; }
		}

		public override string GetAppPath ()
		{
			return appHost.VPath;
		}

		public override string GetAppPathTranslated ()
		{
			return appHost.Path;
		}

		public override string GetFilePathTranslated ()
		{
			if (mappedPath == null)
				mappedPath = MapPath (GetFilePath ());

			return mappedPath;
		}

		public override string GetLocalAddress ()
		{
			return "localhost";
		}

		public override int GetLocalPort ()
		{
			return 0;
		}

		public override string GetPathInfo ()
		{
			return "GetPathInfo"; //???
		}

		public override byte [] GetPreloadedEntityBody ()
		{
			return null;
		}

		public override byte [] GetQueryStringRawBytes ()
		{
			if (queryStringBytes == null) {
				string queryString = GetQueryString ();
				if (queryString != null)
					queryStringBytes = Encoding.GetBytes (queryString);
			}

			return queryStringBytes;
		}

		public override string GetRawUrl ()
		{
			string queryString = GetQueryString ();
			string path = GetFilePath ();
			if (queryString != null && queryString.Length > 0)
				return path + "?" + queryString;

			return path;
		}

		string DoMapPathEvent (string path)
		{
			if (MapPathEvent != null) {
				MapPathEventArgs args = new MapPathEventArgs (path);
				foreach (MapPathEventHandler evt in MapPathEvent.GetInvocationList ()) {
					evt (this, args);
					if (args.IsMapped)
						return args.MappedPath;
				}
			}

			return null;
		}
		
		public override string MapPath (string path)
		{
			string eventResult = DoMapPathEvent (path);
			if (eventResult != null)
				return eventResult;

			if (path == null || path.Length == 0 || path == appHost.VPath)
				return appHost.Path.Replace ('/', Path.DirectorySeparatorChar);

			if (path [0] == '~' && path.Length > 2 && path [1] == '/')
				path = path.Substring (1);

			int len = appHost.VPath.Length;
			if (path.StartsWith (appHost.VPath + "/"))
				path = path.Substring (len + 1);

			if (path.Length > 0 && path [0] == '/')
				path = path.Substring (1);

			return Path.Combine (appHost.Path, path.Replace ('/', Path.DirectorySeparatorChar));
		}

		protected abstract bool GetRequestData ();

		public void ProcessRequest ()
		{
			if (!GetRequestData ())
				return;

			HttpRuntime.ProcessRequest (this);
		}

		public override void SendCalculatedContentLength (int contentLength)
		{
			//FIXME: Should we ignore this for apache2?
			SendUnknownResponseHeader ("Content-Length", contentLength.ToString ());
		}

		public override void SendKnownResponseHeader (int index, string value)
		{
			if (HeadersSent ())
				return;

			string headerName = HttpWorkerRequest.GetKnownResponseHeaderName (index);
			SendUnknownResponseHeader (headerName, value);
		}

		private void SendStream (Stream stream, long offset, long length)
		{
			if (offset < 0 || length <= 0)
				return;
			
			long stLength = stream.Length;
			if (offset + length > stLength)
				length = stLength - offset;

			if (offset > 0)
				stream.Seek (offset, SeekOrigin.Begin);

			byte [] fileContent = new byte [8192];
			int count = fileContent.Length;
			while (length > 0 && (count = stream.Read (fileContent, 0, count)) != 0) {
				SendResponseFromMemory (fileContent, count);
				length -= count;
				count = (int) Math.Min (length, fileContent.Length);
			}
		}

		public override void SendResponseFromFile (string filename, long offset, long length)
		{
			Stream file = null;
			try {
				file = File.OpenRead (filename);
				SendStream (file, offset, length);
			} finally {
				if (file != null)
					file.Close ();
			}
		}

		public override void SendResponseFromFile (IntPtr handle, long offset, long length)
		{
			Stream file = null;
			try {
				file = new FileStream (handle, FileAccess.Read);
				SendStream (file, offset, length);
			} finally {
				if (file != null)
					file.Close ();
			}
		}
	}
}

