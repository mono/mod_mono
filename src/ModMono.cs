/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo.  All rights
 * reserved.
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
 *        Daniel Lopez Ridruejo (daniel@rawbyte.com)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "mod_mono" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono",
 *    nor may "mod_mono" appear in their name, without prior written
 *    permission of Daniel Lopez Ridruejo.
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


namespace Apache.Web
{
	public class ApacheWorkerRequest : HttpWorkerRequest
	{
	  
	  IntPtr request;
	  IntPtr connection;
	  String protocol;
	  public ApacheWorkerRequest (IntPtr request) {
	    this.request = request;
	    this.connection = Request.GetConnection(request);
	  }
	  public static int Main() {
	    return 1;
	  }
		
		public override void EndOfRequest () {
		}

		public override void FlushResponse (bool finalFlush) {
		  Connection.Flush(connection);
		  //if (finalFlush) {
		  //  CloseConnection();
		  //}
		}

		public override void CloseConnection () {
		  Connection.Close(connection);
		}

		public override string GetHttpVerbName () {
		  return Request.GetHttpVerbName(request);
		}
		public override string GetHttpVersion () {
		  return Request.GetHttpVersion(request);
		}
		public override string GetProtocol () {
		  return Request.GetProtocol(request);
		}
		
		public override string GetLocalAddress () {
		  return Connection.GetLocalAddress(connection);
		}
		public override  int GetLocalPort () {
		  return Request.GetServerPort(request);
		}

		public override string GetQueryString () {
		  return Request.GetQueryString(request);
		}

		public override string GetRawUrl () {
		  return Request.GetUnparsedUri(request);
		}
		public override string GetRemoteAddress () {
		  return Connection.GetRemoteAddress(connection);
		}


		public override int GetRemotePort () {
		  return Connection.GetRemotePort(connection);
		}

		public override string GetServerVariable (string name) {
		  return Request.GetServerVariable(request, name);
		}

		public override string GetUriPath () {
		  return Request.GetUri(request);
		}

		public override void SendKnownResponseHeader (int index, string value) {
		  Request.SetResponseHeader(request, GetKnownResponseHeaderName(index), value);
		}

		public override void SendResponseFromFile (IntPtr handle, long offset, long length){
		}
		public override void SendResponseFromFile (string filename, long offset, long length){
		}
		public override void SendResponseFromMemory (byte [] data, int length){

		  Request.SendResponseFromMemory(request, data, length);
		}

		public override void SendStatus (int statusCode, string statusDescription){
		}

		public override void SendUnknownResponseHeader (string name, string value){
		  Request.SetResponseHeader(request, name, value);
		}

		public void ProcessRequest () {
		  Request.SetResponseHeader(request, "Content-Type", "text/html");
		  HttpRuntime.ProcessRequest(this);
		}

		public override bool IsClientConnected () {
		  return true;
		}

		public override string GetFilePath () {
		    return Request.GetFileName(request);
		}

		public override string GetFilePathTranslated() {
		  return Request.GetFileName(request);
		}

		public override string GetAppPath() {
		  return Path.GetDirectoryName(Request.GetFileName(request));
		}

		public override string GetAppPathTranslated() {
		  return Path.GetDirectoryName(Request.GetFileName(request));
		}

                public override string GetRemoteName () {
		  return Connection.GetRemoteName(connection);		  
		}

                public override string GetUnknownRequestHeader (string name) {
		  return Request.GetRequestHeader(request, name);
		}

                public override string GetKnownRequestHeader (int index) {
		  return Request.GetRequestHeader(request, GetKnownRequestHeaderName(index));
		}
	}
}


namespace Apache.Web {
  public class Request {
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetProtocol (IntPtr request);

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetAppPathTranslated (IntPtr request);
    
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetHttpVersion (IntPtr request);
    
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetHttpVerbName (IntPtr request);
    
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static void SendResponseFromMemory (IntPtr request, byte[] data, int length);

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static void SetResponseHeader (IntPtr request, string name, string value);

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetRequestHeader (IntPtr request, string name);
    
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static IntPtr GetConnection (IntPtr request);		

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetServerVariable (IntPtr request, string name);		

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetFileName (IntPtr request);		

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetUri (IntPtr request);		

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetUnparsedUri (IntPtr request);		

    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static string GetQueryString (IntPtr request);		

    // May be different from Connection.GetLocalPort depending on Apache configuration,
    // for things like self referential URLs, etc.
    [MethodImplAttribute(MethodImplOptions.InternalCall)]
      extern public static int GetServerPort (IntPtr request);
  }
public class Connection {
  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static string GetRemoteAddress (IntPtr connection);

  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static string GetRemoteName (IntPtr connection);
  
  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static string GetLocalAddress (IntPtr connection);

  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static int GetLocalPort (IntPtr connection);

  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static int GetRemotePort (IntPtr connection);

  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static void Flush (IntPtr connection);

  [MethodImplAttribute(MethodImplOptions.InternalCall)]
    extern public static void Close (IntPtr connection);
}
}




