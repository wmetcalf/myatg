using System; using System.IO; using System.Text; using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Pkcs;

// Standalone probe for myatg issue #4: does CryptSIPVerifyIndirectData return 0 or nonzero on
// SUCCESS? myatg does `contentOk = vf(...)==0`, which is only correct if success is 0.
// Interop below is copied verbatim from myatg.cs so the calling convention is identical.
public class SipProbe {
  const uint GR=0x80000000,FSR=1,OE=3;
  [StructLayout(LayoutKind.Sequential)] struct BLOB { public uint cb; public IntPtr p; }
  [StructLayout(LayoutKind.Sequential)] struct ALGID { public IntPtr oid; public BLOB par; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SUBJ { public uint cbSize; public IntPtr pgType; public IntPtr hFile; [MarshalAs(UnmanagedType.LPWStr)] public string file; [MarshalAs(UnmanagedType.LPWStr)] public string disp; public uint r1; public uint ver; public IntPtr hProv; public ALGID dig; public uint flags; public uint enc; public uint r2; public uint capi; public uint sec; public uint idx; public uint uchoice; public IntPtr pun; public IntPtr pcd; }
  [StructLayout(LayoutKind.Sequential)] struct IND { public IntPtr dataOid; public BLOB dataVal; public ALGID algo; public BLOB digest; }
  [StructLayout(LayoutKind.Sequential)] struct DISP { public uint cbSize; public IntPtr hSIP; public IntPtr pfGet; public IntPtr pfPut; public IntPtr pfCreate; public IntPtr pfVerify; public IntPtr pfRemove; }
  delegate int VerifyFn(ref SUBJ ps, ref IND ind);
  [DllImport("crypt32.dll",CharSet=CharSet.Unicode)] static extern bool CryptSIPRetrieveSubjectGuid(string f,IntPtr h,ref Guid g);
  [DllImport("crypt32.dll")] static extern bool CryptSIPLoad(ref Guid g,uint fl,ref DISP d);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern bool CryptAcquireContext(ref IntPtr p,string c,string pr,uint t,uint f);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr se,uint d,uint f,IntPtr t);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll")] static extern bool CryptReleaseContext(IntPtr p, uint f);
  [DllImport("kernel32.dll")] static extern uint GetLastError();

  static int TLV(byte[] b,int o,out int hl,out int ln){
    int tag=b[o]; int p=o+1; int l=b[p++];
    if(l>=0x80){ int n=l&0x7F; l=0; for(int i=0;i<n;i++) l=(l<<8)|b[p++]; }
    hl=p-o; ln=l; return tag; }
  static byte[] Sub(byte[] b,int o,int l){ var r=new byte[l]; Array.Copy(b,o,r,0,l); return r; }
  static string Oid(byte[] b){
    var s=new StringBuilder(); long v=0; int len=0; bool first=true;
    for(int i=0;i<b.Length;i++){
      v=(v<<7)|(uint)(b[i]&0x7F); len++;
      if((b[i]&0x80)==0){
        if(first){ long x=v<40?0:(v<80?1:2); s.Append(x).Append('.').Append(v-40*x); first=false; }
        else s.Append('.').Append(v);
        v=0; len=0; } }
    return s.ToString(); }

  static byte[] ScriptPkcs7(string path){
    var sb=new StringBuilder(); bool inb=false; string firstBody=null; int bodyLines=0;
    var lines=new System.Collections.Generic.List<string>();
    using(var sr=new StreamReader(path,Encoding.GetEncoding(28591),true)){ string t; while((t=sr.ReadLine())!=null) lines.Add(t); }
    foreach(var raw in lines){
      string t=raw.Trim();
      if(t.IndexOf("Begin signature block",StringComparison.OrdinalIgnoreCase)>=0){ inb=true; continue; }
      if(t.IndexOf("End signature block",StringComparison.OrdinalIgnoreCase)>=0){ inb=false; continue; }
      if(!inb) continue;
      // Strip whatever comment framing this platform used: a leading '#', then an optional "SIG #".
      string v=t.TrimStart('#').Trim();
      if(v.StartsWith("SIG #",StringComparison.OrdinalIgnoreCase)) v=v.Substring(5).Trim();
      if(v.Length==0) continue;
      if(firstBody==null) firstBody=t.Length>60?t.Substring(0,60):t;
      bodyLines++; sb.Append(v); }
    Console.WriteLine("  scrape: "+bodyLines+" body lines, first="+(firstBody??"<none>"));
    if(sb.Length==0) return null;
    try{ return Convert.FromBase64String(sb.ToString()); }
    catch(Exception e){ Console.WriteLine("  base64 decode failed: "+e.Message); return null; } }

  static int Call(string path, byte[] dataValB, string dataOid, string algoOid, byte[] digest, out uint gle){
    IntPtr pg=IntPtr.Zero,sdig=IntPtr.Zero,hProv=IntPtr.Zero,hFile=IntPtr.Zero; gle=0;
    var ind=new IND();
    try{
      Guid sip=Guid.Empty;
      if(!CryptSIPRetrieveSubjectGuid(path,IntPtr.Zero,ref sip)){ Console.WriteLine("    CryptSIPRetrieveSubjectGuid FAILED gle="+GetLastError()); return int.MinValue; }
      var di=new DISP(); di.cbSize=(uint)Marshal.SizeOf(typeof(DISP));
      if(!CryptSIPLoad(ref sip,0,ref di)){ Console.WriteLine("    CryptSIPLoad FAILED gle="+GetLastError()); return int.MinValue; }
      var vf=(VerifyFn)Marshal.GetDelegateForFunctionPointer(di.pfVerify,typeof(VerifyFn));
      hFile=CreateFile(path,GR,FSR,IntPtr.Zero,OE,0,IntPtr.Zero);
      bool provOk=CryptAcquireContext(ref hProv,null,null,24,0xF0000000);
      if(hFile==new IntPtr(-1)||!provOk){ Console.WriteLine("    setup failed hFile="+hFile+" prov="+provOk); return int.MinValue; }
      ind.dataOid=Marshal.StringToHGlobalAnsi(dataOid);
      ind.dataVal.cb=(uint)dataValB.Length; ind.dataVal.p=Marshal.AllocHGlobal(dataValB.Length); Marshal.Copy(dataValB,0,ind.dataVal.p,dataValB.Length);
      ind.algo.oid=Marshal.StringToHGlobalAnsi(algoOid);
      ind.digest.cb=(uint)digest.Length; ind.digest.p=Marshal.AllocHGlobal(digest.Length); Marshal.Copy(digest,0,ind.digest.p,digest.Length);
      pg=Marshal.AllocHGlobal(16); Marshal.StructureToPtr(sip,pg,false);
      sdig=Marshal.StringToHGlobalAnsi(algoOid);
      var s=new SUBJ(); s.cbSize=(uint)Marshal.SizeOf(typeof(SUBJ)); s.pgType=pg; s.hFile=hFile; s.file=path; s.enc=0x10001; s.hProv=hProv; s.dig.oid=sdig;
      int rc=vf(ref s, ref ind); gle=GetLastError();
      return rc;
    } finally {
      if(ind.dataOid!=IntPtr.Zero)Marshal.FreeHGlobal(ind.dataOid);
      if(ind.dataVal.p!=IntPtr.Zero)Marshal.FreeHGlobal(ind.dataVal.p);
      if(ind.algo.oid!=IntPtr.Zero)Marshal.FreeHGlobal(ind.algo.oid);
      if(ind.digest.p!=IntPtr.Zero)Marshal.FreeHGlobal(ind.digest.p);
      if(pg!=IntPtr.Zero)Marshal.FreeHGlobal(pg); if(sdig!=IntPtr.Zero)Marshal.FreeHGlobal(sdig);
      if(hProv!=IntPtr.Zero)CryptReleaseContext(hProv,0);
      if(hFile!=IntPtr.Zero&&hFile!=new IntPtr(-1))CloseHandle(hFile); } }

  public static int Main(string[] a){
    string path=a[0];
    byte[] der=ScriptPkcs7(path);
    if(der==null){ Console.WriteLine("no signature block"); return 2; }
    var cms=new SignedCms(); cms.Decode(der);
    byte[] ec=cms.ContentInfo.Content;
    int hl,ln; TLV(ec,0,out hl,out ln); int c0=hl; int hl0,ln0; TLV(ec,c0,out hl0,out ln0); int d0=c0+hl0;
    int hA,lA; TLV(ec,d0,out hA,out lA); string dataOid=Oid(Sub(ec,d0+hA,lA));
    int vOff=d0+hA+lA; int hV,lV; TLV(ec,vOff,out hV,out lV); byte[] dataVal=Sub(ec,vOff,hV+lV);
    int c1=c0+hl0+ln0; int hl1,ln1; TLV(ec,c1,out hl1,out ln1); int m0=c1+hl1;
    int hAi,lAi; TLV(ec,m0,out hAi,out lAi); int ao=m0+hAi; int hAo,lAo; TLV(ec,ao,out hAo,out lAo);
    string algoOid=Oid(Sub(ec,ao+hAo,lAo));
    int dOff=m0+hAi+lAi; int hD,lD; TLV(ec,dOff,out hD,out lD); byte[] digest=Sub(ec,dOff+hD,lD);
    Console.WriteLine("  parsed: dataOid="+dataOid+" algoOid="+algoOid+" digest="+BitConverter.ToString(digest).Replace("-","").ToLower().Substring(0,16)+"... ("+digest.Length+" bytes)");

    uint g1,g2;
    Console.WriteLine("  [A] CORRECT digest (the one the file is actually signed with):");
    int rcGood=Call(path,dataVal,dataOid,algoOid,digest,out g1);
    Console.WriteLine("      pfVerify returned "+rcGood+" (0x"+rcGood.ToString("X8")+")  GetLastError="+g1);

    byte[] bad=(byte[])digest.Clone(); bad[0]^=0xFF;
    Console.WriteLine("  [B] CORRUPTED digest (first byte flipped — content does NOT match):");
    int rcBad=Call(path,dataVal,dataOid,algoOid,bad,out g2);
    Console.WriteLine("      pfVerify returned "+rcBad+" (0x"+rcBad.ToString("X8")+")  GetLastError="+g2);

    Console.WriteLine();
    Console.WriteLine("  myatg computes: contentOk = (pfVerify(...) == 0)");
    Console.WriteLine("    correct digest -> contentOk would be "+(rcGood==0));
    Console.WriteLine("    corrupted      -> contentOk would be "+(rcBad==0));
    if(rcGood!=int.MinValue && rcBad!=int.MinValue){
      if(rcGood!=0 && rcBad==0){ Console.WriteLine("  OK: pfVerify is a BOOL (nonzero=success), which is what myatg now assumes with !=0."); return 0; }
      if(rcGood==0 && rcBad!=0){ Console.WriteLine("  FAIL: pfVerify returned 0 on SUCCESS — myatg's !=0 would be inverted on this platform."); return 1; }
      Console.WriteLine("  FAIL: inconclusive, both calls returned "+rcGood+"/"+rcBad+" — the SIP is not comparing our digest."); return 1;
    }
    Console.WriteLine("  FAIL: could not reach pfVerify."); return 1; } }
