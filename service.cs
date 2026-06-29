using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

// SCM-hosted service wrapper. Launched by Windows via the --service flag.
// internal (not public): its ctor takes the internal ServeOpts, so a public class
// would trip CS0051 (inconsistent accessibility). ServiceBase.Run needs no public type.
internal class MyatgService : ServiceBase {
  Validator.ServeOpts _opts;
  Thread _t;
  public MyatgService(Validator.ServeOpts o){ this.ServiceName="myatg"; _opts=o; }
  protected override void OnStart(string[] args){
    _t = new Thread(delegate(){ Validator.ServeHttp(_opts); });
    _t.IsBackground = true;
    _t.Start();
  }
  protected override void OnStop(){
    Validator.StopHttp();
    if(_t!=null) _t.Join(5000);
  }
}

public partial class Validator {
  internal static void RunService(ServeOpts o){
    ServiceBase.Run(new ServiceBase[]{ new MyatgService(o) });
  }

  static int RunTool(string file, string args){
    ProcessStartInfo psi = new ProcessStartInfo(file, args);
    psi.UseShellExecute=false; psi.RedirectStandardOutput=true; psi.RedirectStandardError=true;
    Process p = Process.Start(psi);
    string outp=p.StandardOutput.ReadToEnd(); string err=p.StandardError.ReadToEnd();
    p.WaitForExit();
    if(p.ExitCode!=0){ Console.Error.WriteLine(file+" rc="+p.ExitCode+": "+outp+err); }
    return p.ExitCode;
  }

  internal static int InstallService(ServeOpts o){
    string exe = Process.GetCurrentProcess().MainModule.FileName;
    string prefix = "http://"+o.Bind+":"+o.Port+"/";
    // binPath value: quoted exe path + service args. sc wants the whole value quoted,
    // with the inner exe-path quotes escaped as \".
    string binVal = "\\\""+exe+"\\\" --service --bind "+o.Bind+" --port "+o.Port+" --rev "+o.Rev+" --scripts "+o.Scripts;
    int rc = RunTool("sc.exe", "create myatg binPath= \""+binVal+"\" start= auto obj= \"NT SERVICE\\myatg\" DisplayName= \"myatg validator\"");
    if(rc!=0) return rc;
    RunTool("sc.exe", "failure myatg reset= 60 actions= restart/5000/restart/5000/restart/5000");
    int aclRc = RunTool("netsh", "http add urlacl url="+prefix+" user=\"NT SERVICE\\myatg\"");
    if(aclRc!=0) Console.Error.WriteLine("warning: urlacl add failed (rc="+aclRc+"); service may fail to bind");
    return RunTool("sc.exe", "start myatg");
  }

  internal static int UninstallService(ServeOpts o){
    // best-effort stop, remove the scoped urlacl, then delete the service.
    RunTool("sc.exe", "stop myatg");
    Thread.Sleep(1000);
    string prefix="http://"+o.Bind+":"+o.Port+"/";
    RunTool("netsh", "http delete urlacl url="+prefix);
    return RunTool("sc.exe", "delete myatg");
  }
}
