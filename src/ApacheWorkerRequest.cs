/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo.
 *           (c) 2002 Ximian, Inc.
 *           All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by 
 *        Daniel Lopez Ridruejo (daniel@rawbyte.com) and
 *        Ximian Inc. (http://www.ximian.com)"
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "mod_mono" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono",
 *    nor may "mod_mono" appear in their name, without prior written
 *    permission of Daniel Lopez Ridruejo and Ximian Inc.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL DANIEL LOPEZ RIDRUEJO OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
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
			//TODO: should the status of the response be set here?
		}

		public override void SendUnknownResponseHeader (string name, string value)
		{
			request.SetResponseHeader (name, value);
		}

		public override bool IsClientConnected ()
		{
			return true;
		}

		public override string GetFilePath ()
		{
			if (path == null)
				path = request.GetFileName ();

			return path;
		}
		
		// Until we fix MonoWorkerRequest Map()
		public override string GetFilePathTranslated () {
		  return request.GetFileName();
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

		public override string GetKnownRequestHeader (int index)
		{
			return request.GetRequestHeader (GetKnownRequestHeaderName (index));
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

