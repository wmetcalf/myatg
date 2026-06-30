using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;

public partial class Validator {
  internal class ServeOpts {
    public string Bind = "127.0.0.1";
    public int Port = 8137;
    public string Token = null;
    public bool AllowInsecure = false;
    public string Rev = "online";
    public string Scripts = "ps";
    public int MaxConcurrency = 4;
  }

  static volatile bool httpStop = false;
  static HttpListener httpListener = null;

  internal static bool IsLoopback(string addr){
    if(addr==null) return false;
    string a=addr.Trim().ToLowerInvariant();
    if(a=="localhost"||a=="127.0.0.1"||a=="::1") return true;
    if(a.StartsWith("127.")) return true;
    return false;
  }

  internal static void StopHttp(){
    httpStop = true;
    try { if(httpListener!=null) httpListener.Stop(); } catch {}
  }

  // Start the HTTP server and block until stopped. Returns a process exit code.
  internal static int ServeHttp(ServeOpts o){
    if(!IsLoopback(o.Bind) && o.Token==null && !o.AllowInsecure){
      Console.Error.WriteLine("refusing to bind non-loopback address "+o.Bind+" without --token (use --allow-insecure to override)");
      return 2;
    }
    string prefix = "http://"+o.Bind+":"+o.Port+"/";
    httpListener = new HttpListener();
    httpListener.Prefixes.Add(prefix);
    try { httpListener.Start(); }
    catch(HttpListenerException ex){
      Console.Error.WriteLine("failed to bind "+prefix+": "+ex.Message);
      Console.Error.WriteLine("hint: reserve the URL once (elevated):");
      Console.Error.WriteLine("  netsh http add urlacl url="+prefix+" user=\""+Environment.UserDomainName+"\\"+Environment.UserName+"\"");
      Console.Error.WriteLine("or install the service: myatg --install-service");
      return 2;
    }
    Console.Error.WriteLine("myatg http serve listening on "+prefix);
    Prime(o);   // warm CryptoAPI/X509 chain engine + JIT before accepting, so request #1 isn't cold
    Semaphore gate = new Semaphore(o.MaxConcurrency, o.MaxConcurrency);
    while(!httpStop){
      HttpListenerContext ctx;
      try { ctx = httpListener.GetContext(); }
      catch(HttpListenerException){ break; }
      catch(InvalidOperationException){ break; }
      // Acquire the gate IN the accept loop (not inside the work item): this blocks GetContext from
      // accepting past MaxConcurrency in-flight, so the listener backlog applies backpressure instead
      // of unbounded contexts/threads piling up under a connection flood.
      gate.WaitOne();
      try {
        ThreadPool.QueueUserWorkItem(delegate(object s){
          try { HandleRequest((HttpListenerContext)s, o); }
          catch(OutOfMemoryException){ throw; }
          catch(Exception){ }
          finally { gate.Release(); }
        }, ctx);
      } catch(Exception){ gate.Release(); }   // queue rejected the item -> release so we don't leak the permit
    }
    return 0;
  }

  // One-time warmup so the first real request doesn't pay cold CryptoAPI/chain-engine init plus the
  // first CRL/OCSP fetch inline (the stdin --serve child is primed the same way by the host). The
  // probe runs the configured rev so an online warmup actually pre-fills the revocation cache.
  // Best-effort: a prime failure (no probe binary, offline) must never stop the server from serving.
  static void Prime(ServeOpts o){
    try {
      string probe = Path.Combine(Environment.SystemDirectory, "whoami.exe");
      if(File.Exists(probe)) ValidateFile(probe, o.Rev, o.Scripts);
    } catch(OutOfMemoryException){ throw; } catch(Exception){}
  }

  static void HandleRequest(HttpListenerContext ctx, ServeOpts o){
    HttpListenerRequest req = ctx.Request;
    HttpListenerResponse res = ctx.Response;
    try {
      string path = req.Url.AbsolutePath;
      if(req.HttpMethod=="GET" && path=="/healthz"){ WriteJson(res, 200, "{\"ok\":true}"); return; }
      if(o.Token!=null){
        string hdr=req.Headers["Authorization"];
        string bearer=(hdr!=null && hdr.StartsWith("Bearer ")) ? hdr.Substring(7) : null;
        if(!FixedEquals(o.Token, bearer)){ WriteJson(res, 401, "{\"error\":\"unauthorized\"}"); return; }
      }
      if(path!="/validate"){ WriteJson(res, 404, "{\"error\":\"not found\"}"); return; }
      if(req.HttpMethod!="POST"){ WriteJson(res, 405, "{\"error\":\"method not allowed\"}"); return; }
      if(req.ContentLength64 > maxBytes){ WriteJson(res, 413, ErrJson(null,"UnknownError","file too large")); return; }
      string rev=o.Rev, scripts=o.Scripts;
      var q=req.QueryString;
      if(q["rev"]!=null) rev=q["rev"];
      if(q["scripts"]!=null) scripts=q["scripts"];
      // The extension is part of the verdict: ValidateFile routes .rdp to the RDP validator
      // and script SIP verification (.ps1/.vbs/.js/...) keys on it. The host POSTs the original
      // name as ?name=; preserve a sanitized extension on the temp file (else everything lands
      // as .tmp and signed scripts read NotSigned / .rdp takes the wrong path). Mirrors the
      // guest-agent's Scan-Path: keep only a safe ^\.[A-Za-z0-9]{1,8}$ extension, else none.
      string tmp = Path.Combine(Path.GetTempPath(), "myatg_"+Guid.NewGuid().ToString("N")+SafeExt(q["name"]));
      try {
        long total=0; bool tooBig=false;
        using(FileStream fs=new FileStream(tmp, FileMode.Create, FileAccess.Write)){
          byte[] buf=new byte[65536]; int r; Stream ins=req.InputStream;
          while((r=ins.Read(buf,0,buf.Length))>0){
            total+=r;
            if(total>maxBytes){ tooBig=true; break; }
            fs.Write(buf,0,r);
          }
        }
        if(tooBig){ WriteJson(res, 413, ErrJson(null,"UnknownError","file too large")); return; }
        if(total==0){ WriteJson(res, 400, ErrJson(null,"UnknownError","empty body")); return; }
        string verdict;
        try { verdict = ValidateFile(tmp, rev, scripts); }
        catch(OutOfMemoryException){ throw; }
        catch(Exception e){ verdict = ErrJson(null,"UnknownError",e.GetType().Name); }
        WriteJson(res, 200, verdict);
      } finally {
        try { File.Delete(tmp); } catch {}
      }
    }
    catch(OutOfMemoryException){ throw; }
    catch(Exception){ try { WriteJson(res, 500, "{\"error\":\"internal\"}"); } catch {} }
  }

  // Constant-time compare so the token check leaks no timing signal.
  static bool FixedEquals(string a, string b){
    if(a==null||b==null) return false;
    byte[] x=Encoding.UTF8.GetBytes(a), y=Encoding.UTF8.GetBytes(b);
    if(y.Length==0) return x.Length==0;   // an empty bearer ('Authorization: Bearer ') must 401, not index y[0] -> crash -> 500
    int diff = x.Length ^ y.Length;
    for(int i=0;i<x.Length;i++) diff |= x[i] ^ y[(i<y.Length)?i:0];
    return diff==0;
  }

  // Extract a safe extension from a request-supplied filename: leading '.', then 1-8
  // alphanumerics, lowercased. Anything else (no ext, too long, odd chars, path separators)
  // yields "". No exceptions, no path-char parsing — the name is untrusted.
  static string SafeExt(string name){
    if(string.IsNullOrEmpty(name)) return "";
    int dot = name.LastIndexOf('.');
    if(dot < 0 || dot == name.Length-1) return "";
    string ext = name.Substring(dot);
    if(ext.Length < 2 || ext.Length > 9) return "";
    for(int i=1;i<ext.Length;i++){ char c=ext[i]; if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9'))) return ""; }
    return ext.ToLowerInvariant();
  }

  static void WriteJson(HttpListenerResponse res, int code, string body){
    byte[] b = Encoding.UTF8.GetBytes(body);
    res.StatusCode = code;
    res.ContentType = "application/json";
    res.ContentLength64 = b.Length;
    res.OutputStream.Write(b,0,b.Length);
    res.OutputStream.Close();
  }
}
