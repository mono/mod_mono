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
	public class Request
	{
		IntPtr request;
		IntPtr connection;

		public Request (IntPtr request)
		{
			this.request = request;
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static IntPtr GetConnectionInternal (IntPtr request);		

		IntPtr Conn {
			get {
				if (connection == IntPtr.Zero)
					connection = GetConnectionInternal (request);

				return connection;
			}
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetHttpVersionInternal (IntPtr request);

		public string GetProtocol ()
		{
			return GetHttpVersionInternal (request);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetHttpVerbNameInternal (IntPtr request);

		public string GetHttpVerbName ()
		{
			return GetHttpVerbNameInternal (request);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static void SendResponseFromMemoryInternal (IntPtr request, byte[] data, int length);

		public void SendResponseFromMemory (byte [] data, int length)
		{
			SendResponseFromMemoryInternal (request, data, length);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static void SetResponseHeaderInternal (IntPtr request, string name, string value);

		public void SetResponseHeader (string name, string value)
		{
			SetResponseHeaderInternal (request, name, value);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetRequestHeaderInternal (IntPtr request, string name);

		public string GetRequestHeader (string name)
		{
			return GetRequestHeaderInternal (request, name);
		}

		// AliasMatches and RemovePrefix works for now but this should
		// not be done here, but fully in C# in ApacheWorkerRequest.MapPath --daniel
		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int AliasMatches (string uri, string fakeName);

		public string RemovePrefix (string uri, string appPrefix)
		{
		  int l = AliasMatches(uri, appPrefix);
		  if (l < 0) {
		    return uri;
		  } else {
		    return uri.Substring(l + 1);
		  }
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetServerVariableInternal (IntPtr request, string name);		

		public string GetServerVariable (string name)
		{
			return GetServerVariableInternal (request, name);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetUriInternal (IntPtr request);		

		public string GetUri ()
		{
			return GetUriInternal (request);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetFileNameInternal (IntPtr request);		

		public string GetFileName ()
		{
			return GetFileNameInternal (request);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetQueryStringInternal (IntPtr request);		

		public string GetQueryString ()
		{
			return GetQueryStringInternal (request);
		}

		// May be different from Connection.GetLocalPort depending on Apache configuration,
		// for things like self referential URLs, etc.
		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int GetServerPortInternal (IntPtr request);
		
		public int GetServerPort ()
		{
			return GetServerPortInternal (request);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetRemoteAddressInternal (IntPtr connection);

		public string GetRemoteAddress ()
		{
			return GetRemoteAddressInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetRemoteNameInternal (IntPtr connection);

		public string GetRemoteName ()
		{
			return GetRemoteNameInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static string GetLocalAddressInternal (IntPtr connection);

		public string GetLocalAddress ()
		{
			return GetLocalAddressInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int GetLocalPortInternal (IntPtr connection);

		public int GetLocalPort ()
		{
			return GetLocalPortInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int GetRemotePortInternal (IntPtr connection);

		public int GetRemotePort ()
		{
			return GetRemotePortInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static void FlushInternal (IntPtr connection);

		public void Flush ()
		{
			FlushInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static void CloseInternal (IntPtr connection);

		public void Close ()
		{
			CloseInternal (Conn);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int SetupClientBlockInternal (IntPtr request);

		public int SetupClientBlock() 
		{
		  return SetupClientBlockInternal(request);
		} 

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int ShouldClientBlockInternal (IntPtr request);

		public bool ShouldClientBlock() 
		{
		  return ShouldClientBlockInternal(request) != 0;
		} 

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int GetClientBlockInternal (IntPtr request, byte[] bytes, uint size);

		public int GetClientBlock(byte[] bytes, int size) 
		{
		  return GetClientBlockInternal(request, bytes, (uint)size);
		} 

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int SetStatusCodeInternal(IntPtr request, int code);
		
		public void SetStatusCode (int code) 
		{
		  SetStatusCodeInternal(request, code);
		}

		[MethodImplAttribute(MethodImplOptions.InternalCall)]
		extern static int SetStatusLineInternal (IntPtr request, string status);
		
		public void SetStatusLine (string status)
		{
		  SetStatusLineInternal(request, status);
		}
	}
}

