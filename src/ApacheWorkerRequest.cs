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
using System.Web;
using System.Collections;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Mono.ASPNET;

namespace Apache.Web
{
	public class ApacheWorkerRequest : MonoWorkerRequest
	{
		Request request;
		string verb;
		string queryString;
		string protocol;
		string localAddress;
		string remoteAddress;
		string remoteName;
		int localPort;
		int remotePort;
		string path;

		public ApacheWorkerRequest (IApplicationHost appHost, IntPtr request)
			: base (appHost)
		{
			this.request = new Request (request);
		}

		protected override bool GetRequestData ()
		{
			return true;
		}
		
		public override void EndOfRequest ()
		{
		}

		public override bool HeadersSent ()
		{
			//FIXME!!!!: how do we know this?
			return false;
		}
		
		public override void FlushResponse (bool finalFlush)
		{
			request.Flush ();
		}

		public override void CloseConnection ()
		{
		  request.Close ();
		}

		public override string GetHttpVerbName ()
		{
			if (verb == null)
				verb = request.GetHttpVerbName ();

			return verb;
		}

		public override string GetHttpVersion ()
		{
			if (protocol == null)
				protocol = request.GetProtocol ();

			return protocol;
		}

		public override string GetLocalAddress ()
		{
			if (localAddress == null)
				localAddress = request.GetLocalAddress ();

			return localAddress;
		}

		public override int GetLocalPort ()
		{
			if (localPort == 0)
				localPort = request.GetServerPort ();

			return localPort;
		}

		public override string GetQueryString ()
		{
			if (queryString == null)
				queryString = request.GetQueryString ();

			return queryString;
		}

		public override string GetRemoteAddress ()
		{
			if (remoteAddress == null)
				remoteAddress = request.GetRemoteAddress ();

			return remoteAddress;
		}

		public override int GetRemotePort ()
		{
			if (remotePort == 0)
				remotePort = request.GetRemotePort ();

			return remotePort;
		}

		public override string GetServerVariable (string name)
		{
			//TODO: cache them in a hash?
			return request.GetServerVariable (name);
		}

		public override void SendResponseFromMemory (byte [] data, int length)
		{
			request.SendResponseFromMemory (data, length);
		}

		public override void SendStatus (int statusCode, string statusDescription)
		{
		  request.SetStatusCode(statusCode);
		  // Protocol will be added by Apache
		  request.SetStatusLine(String.Format("{0} {1}", statusCode, statusDescription));
		}

		public override void SendUnknownResponseHeader (string name, string value)
		{
			request.SetResponseHeader (name, value);
		}

		public override bool IsClientConnected ()
		{
			return true;
		}

		public override string GetUriPath () {
		  return request.GetUri();
		}

		public override string GetFilePath ()
		{
		  //Docs say it is physical path, but it seems it is the virtual path
			return GetUriPath();
		}
		
		// Until we fix MonoWorkerRequest Map()
		public override string GetFilePathTranslated () {
		  return request.GetFileName();
		}

		public override string MapPath (string path) {
		  return base.MapPath(request.RemovePrefix(path, base.GetAppPath ()));
		}

		public override string GetRemoteName ()
		{
			if (remoteName == null)
				remoteName = request.GetRemoteName ();

			return remoteName;
		}

		public override string GetUnknownRequestHeader (string name)
		{
			return request.GetRequestHeader (name);
		}

		public override string [][] GetUnknownRequestHeaders ()
		{
			/**
			 *FIXME: this should return all the headers whose index in:
			 *   HttpWorkerRequest.GetKnownRequestHeaderIndex (headerName);
			 * is -1. Once we get the value, keep it in a class field.
			 */
			return null;
		}

		public override string GetKnownRequestHeader (int index)
		{
			return request.GetRequestHeader (GetKnownRequestHeaderName (index));
		}

		public override void SendCalculatedContentLength (int contentLength) 
		{
		  // Do nothing, it will be set correctly by Apache in the output content length filter
		}


		public override int ReadEntityBody (byte [] buffer, int size)
		{
		  if (buffer == null || size <= 0 || request.SetupClientBlock() != 0 /* APR_SUCCESS */)
		    return 0;
		  byte [] bytes = new byte [size];
		  int read = 0;
		  if (request.ShouldClientBlock()) {
		    read = request.GetClientBlock(bytes, size);
		  }
		  if ( read > 0 ) {
		    bytes.CopyTo (buffer, 0);
		  }
		  return read;
		}
	}
}

