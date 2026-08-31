using System; using System.Reflection;
// Drives the COMPILED Validator.Oid by reflection. Every malformed case asserts the exception
// MESSAGE, not merely that something threw: an IndexOutOfRange or NullReference must not be able
// to masquerade as the intended "der: ..." rejection.
public class OidTest {
  static MethodInfo M;
  static string Call(byte[] b){ try{ return (string)M.Invoke(null,new object[]{b}); }
    catch(TargetInvocationException e){ return "THROW:"+e.InnerException.Message; } }
  static byte[] Enc(string oid){
    var p=oid.Split('.'); var outb=new System.Collections.Generic.List<byte>();
    var vals=new System.Collections.Generic.List<long>();
    vals.Add(40*long.Parse(p[0])+long.Parse(p[1]));
    for(int i=2;i<p.Length;i++) vals.Add(long.Parse(p[i]));
    foreach(var v0 in vals){ long v=v0; var c=new System.Collections.Generic.List<byte>();
      c.Add((byte)(v&0x7F)); v>>=7;
      while(v>0){ c.Add((byte)((v&0x7F)|0x80)); v>>=7; }
      c.Reverse(); outb.AddRange(c); }
    return outb.ToArray(); }
  static int fail=0;
  static void Valid(string label, byte[] b, string want){
    var got=Call(b);
    if(got!=want){ Console.WriteLine("  FAIL valid {0}: got {1} want {2}",label,got,want); fail++; }
    else Console.WriteLine("  ok   valid {0} -> {1}",label,got); }
  static void Bad(string label, byte[] b, string wantMsg){
    var got=Call(b);
    if(got!="THROW:"+wantMsg){ Console.WriteLine("  FAIL malformed {0}: got {1} want THROW:{2}",label,got,wantMsg); fail++; }
    else Console.WriteLine("  ok   malformed {0} -> {1}",label,got); }
  public static int Main(){
    var asm=Assembly.LoadFrom("myatg.exe");
    M=asm.GetType("Validator").GetMethod("Oid",BindingFlags.NonPublic|BindingFlags.Static);
    if(M==null){ Console.WriteLine("FATAL: Oid not found"); return 2; }

    string[] valid={"0.9.2342.19200300.100.1.25","1.2.840.113549.1.1.11","2.5.29.15","2.5.4.3",
      "2.5.4.0","2.16.840.1.101.3.4.2.1","1.3.6.1.5.5.7.48.2","1.3.6.1.5.5.7.48.1","2.23.140.1.1",
      "1.3.6.1.4.1.311.2.1.11","2.40.0.25","2.47.1","2.48.1","2.100.3","2.999.1"};
    foreach(var o in valid) Valid(o,Enc(o),o);

    // Cap boundary, ACCEPT side: a 9-byte subidentifier holding exactly long.MaxValue must decode.
    // Without this, tightening the cap to len>=8 would go unnoticed.
    var max9=new byte[]{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x7F};
    Valid("9-byte arc == long.MaxValue", max9, "2."+(long.MaxValue-80).ToString());

    // Cap boundary, REJECT side: the smallest 10-byte minimal encoding is 2^63, one past long.
    // Without this, loosening the cap to len>=10 still passed and produced NEGATIVE arcs.
    var over10=new byte[]{0x81,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x80,0x00};
    Bad("10-byte arc == 2^63 (overflows long)", over10, "der: OID subidentifier too large");

    Bad("empty", new byte[0], "der: empty OID");
    Bad("null", null, "der: empty OID");
    Bad("leading 0x80 at offset 0", new byte[]{0x80}, "der: non-minimal OID subidentifier");
    Bad("leading 0x80 then value", new byte[]{0x80,0x01}, "der: non-minimal OID subidentifier");
    Bad("0x80 pad mid-OID (collided with caIssuers)", new byte[]{0x2B,0x80,0x06,0x01,0x05,0x05,0x07,0x30,0x02}, "der: non-minimal OID subidentifier");
    Bad("legit + trailing 0x80 (collided)", new byte[]{0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,0x80}, "der: non-minimal OID subidentifier");
    Bad("trailing continuation", new byte[]{0x2B,0x06,0x81}, "der: truncated OID subidentifier");
    Bad("9 continuation bytes, unterminated", new byte[]{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, "der: truncated OID subidentifier");
    Bad("10 continuation bytes", new byte[]{0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, "der: OID subidentifier too large");

    Console.WriteLine(fail==0?"ALL PASS":"FAILURES="+fail);
    return fail==0?0:1; } }
