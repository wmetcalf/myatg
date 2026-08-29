using System; using System.Reflection;
public class OidTest {
  static MethodInfo M;
  static string Call(byte[] b){ try{ return (string)M.Invoke(null,new object[]{b}); }
    catch(TargetInvocationException e){ return "THROW:"+e.InnerException.Message; } }
  static byte[] Enc(string oid){
    var p=oid.Split('.'); var outb=new System.Collections.Generic.List<byte>();
    long first=40*long.Parse(p[0])+long.Parse(p[1]);
    var vals=new System.Collections.Generic.List<long>(); vals.Add(first);
    for(int i=2;i<p.Length;i++) vals.Add(long.Parse(p[i]));
    foreach(var v0 in vals){ long v=v0; var c=new System.Collections.Generic.List<byte>();
      c.Add((byte)(v&0x7F)); v>>=7;
      while(v>0){ c.Add((byte)((v&0x7F)|0x80)); v>>=7; }
      c.Reverse(); outb.AddRange(c); }
    return outb.ToArray(); }
  public static int Main(){
    var asm=Assembly.LoadFrom("myatg.exe");
    M=asm.GetType("Validator").GetMethod("Oid",BindingFlags.NonPublic|BindingFlags.Static);
    if(M==null){ Console.WriteLine("FATAL: Oid not found"); return 2; }
    int fail=0;
    string[] valid={"0.9.2342.19200300.100.1.25","1.2.840.113549.1.1.11","2.5.29.15","2.5.4.3",
      "2.16.840.1.101.3.4.2.1","1.3.6.1.5.5.7.48.2","1.3.6.1.5.5.7.48.1","2.23.140.1.1",
      "1.3.6.1.4.1.311.2.1.11","2.40.0.25","2.47.1","2.48.1","2.100.3","2.999.1"};
    foreach(var o in valid){ var got=Call(Enc(o));
      if(got!=o){ Console.WriteLine("  FAIL valid {0} -> {1}",o,got); fail++; }
      else Console.WriteLine("  ok   {0}",o); }
    var bad=new System.Collections.Generic.List<byte[]>();
    var names=new string[]{"empty","trailing-continuation","0x80-padded-caIssuers","legit+0x80","overflow 0xFF*12"};
    bad.Add(new byte[0]);
    bad.Add(new byte[]{0x2B,0x06,0x81});
    bad.Add(new byte[]{0x2B,0x80,0x06,0x01,0x05,0x05,0x07,0x30,0x02});
    bad.Add(new byte[]{0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,0x80});
    var ov=new System.Collections.Generic.List<byte>(); ov.Add(0x2B);
    for(int i=0;i<12;i++) ov.Add(0xFF); ov.Add(0x01); bad.Add(ov.ToArray());
    for(int i=0;i<bad.Count;i++){ var got=Call(bad[i]);
      if(!got.StartsWith("THROW:")){ Console.WriteLine("  FAIL malformed {0} -> RETURNED {1}",names[i],got); fail++; }
      else Console.WriteLine("  ok   malformed {0} -> {1}",names[i],got); }
    Console.WriteLine(fail==0?"ALL PASS":"FAILURES="+fail);
    return fail==0?0:1; } }
