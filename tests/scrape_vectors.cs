using System; using System.Reflection;
// Drives the COMPILED Validator.ScriptPkcs7 against a genuinely PowerShell-signed script.
// Before the fix it derived the prefix from "# SIG # Begin signature block" and then required the
// base64 body to start with "# SIG #" -- but PowerShell writes the body with a bare "# ", so the
// scrape returned null for every real signed script.
public class ScrapeTest {
  public static int Main(string[] a){
    var asm=Assembly.LoadFrom("myatg.exe");
    var m=asm.GetType("Validator").GetMethod("ScriptPkcs7",BindingFlags.NonPublic|BindingFlags.Static);
    if(m==null){ Console.WriteLine("FATAL: ScriptPkcs7 not found"); return 2; }
    int fail=0;
    foreach(var path in a){
      byte[] der=null; string err=null;
      try{ der=(byte[])m.Invoke(null,new object[]{path}); }
      catch(TargetInvocationException e){ err=e.InnerException.GetType().Name; }
      if(err!=null){ Console.WriteLine("  {0}: THREW {1}",path,err); fail++; continue; }
      if(der==null){ Console.WriteLine("  {0}: scrape returned NULL (cannot read the signature block)",path); fail++; continue; }
      // prove it is a real PKCS#7 by decoding it
      try{
        var cms=new System.Security.Cryptography.Pkcs.SignedCms(); cms.Decode(der);
        Console.WriteLine("  {0}: scraped {1} bytes, SignedCms decoded, signer={2}",
          path, der.Length, cms.SignerInfos[0].Certificate.Subject);
      }catch(Exception e){ Console.WriteLine("  {0}: scraped {1} bytes but decode failed: {2}",path,der.Length,e.Message); fail++; }
    }
    Console.WriteLine(fail==0?"ALL SCRAPED":"FAILURES="+fail);
    return fail==0?0:1; } }
