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
    Semaphore gate = new Semaphore(o.MaxConcurrency, o.MaxConcurrency);
    while(!httpStop){
      HttpListenerContext ctx;
      try { ctx = httpListener.GetContext(); }
      catch(HttpListenerException){ break; }
      catch(InvalidOperationException){ break; }
      ThreadPool.QueueUserWorkItem(delegate(object s){
        gate.WaitOne();
        try { HandleRequest((HttpListenerContext)s, o); }
        catch(OutOfMemoryException){ throw; }
        catch(Exception){ }
        finally { gate.Release(); }
      }, ctx);
    }
    return 0;
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
      if(req.ContentLength64 > maxBytes){ WriteJson(res, 413, "{\"error\":\"file too large\"}"); return; }
      string rev=o.Rev, scripts=o.Scripts;
      var q=req.QueryString;
      if(q["rev"]!=null) rev=q["rev"];
      if(q["scripts"]!=null) scripts=q["scripts"];
      string tmp = Path.GetTempFileName();
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
        if(tooBig){ WriteJson(res, 413, "{\"error\":\"file too large\"}"); return; }
        if(total==0){ WriteJson(res, 400, "{\"error\":\"empty body\"}"); return; }
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
    int diff = x.Length ^ y.Length;
    for(int i=0;i<x.Length;i++) diff |= x[i] ^ y[(i<y.Length)?i:0];
    return diff==0;
  }

  static void WriteJson(HttpListenerResponse res, int code, string body){
    byte[] b = Encoding.UTF8.GetBytes(body);
    res.StatusCode = code;
    res.ContentType = "application/json";
    res.ContentLength64 = b.Length;
    res.OutputStream.Write(b,0,b.Length);
    res.OutputStream.Close();
  }

  // --- Task 1 temporary stubs (replaced by service.cs in Task 5) ---
  internal static int InstallService(ServeOpts o){ Console.Error.WriteLine("not implemented"); return 1; }
  internal static int UninstallService(ServeOpts o){ Console.Error.WriteLine("not implemented"); return 1; }
  internal static void RunService(ServeOpts o){ ServeHttp(o); }
}
