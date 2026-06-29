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

  // Routing added incrementally. Task 1: only /healthz.
  static void HandleRequest(HttpListenerContext ctx, ServeOpts o){
    HttpListenerRequest req = ctx.Request;
    HttpListenerResponse res = ctx.Response;
    try {
      string path = req.Url.AbsolutePath;
      if(req.HttpMethod=="GET" && path=="/healthz"){ WriteJson(res, 200, "{\"ok\":true}"); return; }
      WriteJson(res, 404, "{\"error\":\"not found\"}");
    }
    catch(OutOfMemoryException){ throw; }
    catch(Exception){ try { WriteJson(res, 500, "{\"error\":\"internal\"}"); } catch {} }
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
