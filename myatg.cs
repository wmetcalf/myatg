using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
public class Validator {
  static readonly Guid GVV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
  const uint WTD_UI_NONE=2,WTD_REVOKE_NONE=0,WTD_CHOICE_FILE=1,WTD_CHOICE_CATALOG=2,WTD_SAV=1,WTD_SAC=2;
  const uint GR=0x80000000,FSR=1,OE=3;
  [StructLayout(LayoutKind.Sequential)] struct BLOB { public uint cb; public IntPtr p; }
  [StructLayout(LayoutKind.Sequential)] struct ALGID { public IntPtr oid; public BLOB par; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct WFI { public uint cb; public string path; public IntPtr hFile; public IntPtr pgKnown; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct WCI { public uint cb; public uint ver; public string cat; public string tag; public string mfile; public IntPtr hMember; public IntPtr pHash; public uint cbHash; public IntPtr pCtx; public IntPtr hCat; }
  [StructLayout(LayoutKind.Sequential)] struct WTD { public uint cb; public IntPtr pcb; public IntPtr psip; public uint ui; public uint rev; public uint uc; public IntPtr pUnion; public uint sa; public IntPtr st; public IntPtr url; public uint pf; public uint uic; public IntPtr ss; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct CATINFO { public uint cb; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string file; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SUBJ { public uint cbSize; public IntPtr pgType; public IntPtr hFile; [MarshalAs(UnmanagedType.LPWStr)] public string file; [MarshalAs(UnmanagedType.LPWStr)] public string disp; public uint r1; public uint ver; public IntPtr hProv; public ALGID dig; public uint flags; public uint enc; public uint r2; public uint capi; public uint sec; public uint idx; public uint uchoice; public IntPtr pun; public IntPtr pcd; }
  [StructLayout(LayoutKind.Sequential)] struct IND { public IntPtr dataOid; public BLOB dataVal; public ALGID algo; public BLOB digest; }
  [StructLayout(LayoutKind.Sequential)] struct DISP { public uint cbSize; public IntPtr hSIP; public IntPtr pfGet; public IntPtr pfPut; public IntPtr pfCreate; public IntPtr pfVerify; public IntPtr pfRemove; }
  delegate int VerifyFn(ref SUBJ ps, ref IND ind);
  [DllImport("wintrust.dll")] static extern int WinVerifyTrust(IntPtr h,[MarshalAs(UnmanagedType.LPStruct)] Guid g,ref WTD d);
  [DllImport("wintrust.dll")] static extern IntPtr WTHelperProvDataFromStateData(IntPtr h);
  [DllImport("wintrust.dll")] static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr p,uint i,bool c,uint ci);
  [DllImport("wintrust.dll")] static extern bool CryptCATAdminAcquireContext(ref IntPtr h,IntPtr g,uint f);
  [DllImport("wintrust.dll",SetLastError=true)] static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr h,ref uint cb,byte[] hash,uint f);
  [DllImport("wintrust.dll")] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr h,byte[] hash,uint cb,uint f,ref IntPtr prev);
  [DllImport("wintrust.dll")] static extern bool CryptCATCatalogInfoFromContext(IntPtr h,ref CATINFO ci,uint f);
  [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr h,IntPtr c,uint f);
  [DllImport("wintrust.dll")] static extern bool CryptCATAdminReleaseContext(IntPtr h,uint f);
  [DllImport("crypt32.dll",CharSet=CharSet.Unicode)] static extern bool CryptSIPRetrieveSubjectGuid(string f,IntPtr h,ref Guid g);
  [DllImport("crypt32.dll")] static extern bool CryptSIPLoad(ref Guid g,uint fl,ref DISP d);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern bool CryptAcquireContext(ref IntPtr p,string c,string pr,uint t,uint f);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateFile(string n,uint a,uint s,IntPtr se,uint d,uint f,IntPtr t);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("advapi32.dll")] static extern bool CryptReleaseContext(IntPtr p, uint f);

  static DateTime? TstGenTime(byte[] tst){ int hl,ln; TLV(tst,0,out hl,out ln); int p=hl,end=hl+ln; while(p<end){ int h,l; int tag=TLV(tst,p,out h,out l); if(tag==0x18){ try{ string s=Encoding.ASCII.GetString(tst,p+h,l).TrimEnd('Z').Replace(',','.').Split('.')[0]; if(s.Length>14) s=s.Substring(0,14); return DateTime.ParseExact(s,"yyyyMMddHHmmss",null,System.Globalization.DateTimeStyles.AssumeUniversal|System.Globalization.DateTimeStyles.AdjustToUniversal); }catch{ return null; } } p+=h+l; } return null; }
  static X509Certificate2 CertFromSgnr(IntPtr sg){ if(sg==IntPtr.Zero)return null; if(Marshal.ReadInt32(sg,12)<1)return null; IntPtr ch=Marshal.ReadIntPtr(sg,16); if(ch==IntPtr.Zero)return null; IntPtr pc=Marshal.ReadIntPtr(ch,8); if(pc==IntPtr.Zero)return null; try{return new X509Certificate2(pc);}catch{return null;} }
  static int WVT(ref WTD wd,out X509Certificate2 signer,out X509Certificate2 tsa,out DateTime? signTime){ signer=null;tsa=null;signTime=null; int res=WinVerifyTrust(IntPtr.Zero,GVV2,ref wd); if(wd.st!=IntPtr.Zero){ IntPtr pv=WTHelperProvDataFromStateData(wd.st); if(pv!=IntPtr.Zero){ signer=CertFromSgnr(WTHelperGetProvSignerFromChain(pv,0,false,0)); IntPtr cs=WTHelperGetProvSignerFromChain(pv,0,true,0); if(cs!=IntPtr.Zero){ tsa=CertFromSgnr(cs); long ft=Marshal.ReadInt64(cs,4); if(ft>0){ try{signTime=DateTime.FromFileTimeUtc(ft);}catch{} } } } } wd.sa=WTD_SAC; WinVerifyTrust(IntPtr.Zero,GVV2,ref wd); return res; }
  static int VerifyBinary(string path,out X509Certificate2 signer,out string st,out X509Certificate2 tsa,out DateTime? signTime){ tsa=null; signTime=null;
    signer=null; st="None";
    var fi=new WFI(); fi.cb=(uint)Marshal.SizeOf(typeof(WFI)); fi.path=path; IntPtr pf=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WFI)));
    int res;
    try{ Marshal.StructureToPtr(fi,pf,false);
      var wd=new WTD(); wd.cb=(uint)Marshal.SizeOf(typeof(WTD)); wd.ui=WTD_UI_NONE; wd.rev=WTD_REVOKE_NONE; wd.uc=WTD_CHOICE_FILE; wd.pUnion=pf; wd.sa=WTD_SAV;
      res=WVT(ref wd,out signer,out tsa,out signTime);
    } finally{ Marshal.FreeHGlobal(pf); }
    if((uint)res!=0x800B0100){ if(res==0||signer!=null) st="Embedded"; return res; }
    IntPtr hFile=CreateFile(path,GR,FSR,IntPtr.Zero,OE,0,IntPtr.Zero); if(hFile==IntPtr.Zero||hFile==new IntPtr(-1)) return res;
    try{ uint cb=0; CryptCATAdminCalcHashFromFileHandle(hFile,ref cb,null,0); if(cb==0)return res; byte[] hash=new byte[cb]; if(!CryptCATAdminCalcHashFromFileHandle(hFile,ref cb,hash,0))return res;
      string tag=BitConverter.ToString(hash).Replace("-",""); IntPtr hCA=IntPtr.Zero; if(!CryptCATAdminAcquireContext(ref hCA,IntPtr.Zero,0))return res;
      try{ IntPtr prev=IntPtr.Zero; IntPtr hCat=CryptCATAdminEnumCatalogFromHash(hCA,hash,cb,0,ref prev); if(hCat==IntPtr.Zero)return res;
        var ci=new CATINFO(); ci.cb=(uint)Marshal.SizeOf(typeof(CATINFO)); if(!CryptCATCatalogInfoFromContext(hCat,ref ci,0)){CryptCATAdminReleaseCatalogContext(hCA,hCat,0);return res;}
        IntPtr pH=IntPtr.Zero, pc2=IntPtr.Zero;
        try{
          pH=Marshal.AllocHGlobal(hash.Length); Marshal.Copy(hash,0,pH,hash.Length);
          var c2=new WCI(); c2.cb=(uint)Marshal.SizeOf(typeof(WCI)); c2.cat=ci.file; c2.tag=tag; c2.mfile=path; c2.hMember=hFile; c2.pHash=pH; c2.cbHash=cb; c2.hCat=hCA;
          pc2=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WCI))); Marshal.StructureToPtr(c2,pc2,false);
          var wd2=new WTD(); wd2.cb=(uint)Marshal.SizeOf(typeof(WTD)); wd2.ui=WTD_UI_NONE; wd2.rev=WTD_REVOKE_NONE; wd2.uc=WTD_CHOICE_CATALOG; wd2.pUnion=pc2; wd2.sa=WTD_SAV;
          int cres=WVT(ref wd2,out signer,out tsa,out signTime); if(cres==0||signer!=null) st="Catalog"; return cres;
        } finally{ if(pc2!=IntPtr.Zero) Marshal.FreeHGlobal(pc2); if(pH!=IntPtr.Zero) Marshal.FreeHGlobal(pH); CryptCATAdminReleaseCatalogContext(hCA,hCat,0); }
      } finally{ CryptCATAdminReleaseContext(hCA,0); }
    } finally{ CloseHandle(hFile); }
  }
  static int TLV(byte[] b,int o,out int hl,out int ln){ int tag=b[o]; int p=o+1; int l=b[p++]; if(l>=0x80){int n=l&0x7F;l=0;for(int i=0;i<n;i++)l=(l<<8)|b[p++];} hl=p-o; ln=l; return tag; }
  static byte[] Sub(byte[] b,int o,int l){ var r=new byte[l]; Array.Copy(b,o,r,0,l); return r; }
  static string Oid(byte[] b){ var s=new StringBuilder(); s.Append(b[0]/40).Append('.').Append(b[0]%40); long v=0; for(int i=1;i<b.Length;i++){v=(v<<7)|(uint)(b[i]&0x7F); if((b[i]&0x80)==0){s.Append('.').Append(v);v=0;}} return s.ToString(); }
  static byte[] ScriptPkcs7(string path){
    try{ if(new FileInfo(path).Length > maxBytes) return null; }catch{ return null; }
    // Detect the BOM (UTF-16LE/BE, UTF-8 — normal for signed .ps1) and decode with it;
    // fall back to ISO-8859-1 for BOM-less ANSI/ASCII (byte-preserving for the SIG markers).
    string[] lines;
    try{ var ll=new System.Collections.Generic.List<string>(); using(var sr=new StreamReader(path,Encoding.GetEncoding(28591),true)){ string li; while((li=sr.ReadLine())!=null) ll.Add(li); } lines=ll.ToArray(); }catch{ return null; }
    string pfx=null; var sb=new StringBuilder(); bool inb=false;
    foreach(string raw in lines){ string t=raw.Trim();
      int bi=t.IndexOf("Begin signature block"); if(bi>0){ pfx=t.Substring(0,bi).Trim(); inb=true; continue; }
      if(t.Contains("End signature block")){ inb=false; continue; }
      if(inb && pfx!=null && t.StartsWith(pfx)) sb.Append(t.Substring(pfx.Length).Trim()); }
    if(sb.Length==0) return null;
    try{ return Convert.FromBase64String(sb.ToString()); }catch{ return null; }
  }
  static bool VerifyScript(string path,byte[] der,out X509Certificate2 signer,out bool contentOk,out X509Certificate2 tsa,out DateTime? signTime){ tsa=null; signTime=null;
    signer=null; contentOk=false; bool sigOk;
    var cms=new SignedCms(); cms.Decode(der); embeddedCerts=cms.Certificates; try{ cms.CheckSignature(true); sigOk=true; }catch{ sigOk=false; }
    signer=cms.SignerInfos[0].Certificate;
    try{ var csi=cms.SignerInfos[0].CounterSignerInfos; if(csi.Count>0){ tsa=csi[0].Certificate; foreach(var at in csi[0].SignedAttributes){ if(at.Oid.Value=="1.2.840.113549.1.9.5"&&at.Values.Count>0){ try{ var t=new Pkcs9SigningTime(at.Values[0].RawData); signTime=t.SigningTime.ToUniversalTime(); }catch{} } } } }catch{}
    if(tsa==null){ try{ foreach(var ua in cms.SignerInfos[0].UnsignedAttributes){ if(ua.Oid.Value=="1.3.6.1.4.1.311.3.3.1"&&ua.Values.Count>0){ var tok=new SignedCms(); tok.Decode(ua.Values[0].RawData); tsa=tok.SignerInfos[0].Certificate; signTime=TstGenTime(tok.ContentInfo.Content); } } }catch{} }
    byte[] ec=cms.ContentInfo.Content;
    int hl,ln; TLV(ec,0,out hl,out ln); int c0=hl; int hl0,ln0; TLV(ec,c0,out hl0,out ln0); int d0=c0+hl0;
    int hA,lA; TLV(ec,d0,out hA,out lA); string dataOid=Oid(Sub(ec,d0+hA,lA)); int vOff=d0+hA+lA; int hV,lV; TLV(ec,vOff,out hV,out lV); byte[] dataVal=Sub(ec,vOff,hV+lV);
    int c1=c0+hl0+ln0; int hl1,ln1; TLV(ec,c1,out hl1,out ln1); int m0=c1+hl1; int hAi,lAi; TLV(ec,m0,out hAi,out lAi); int ao=m0+hAi; int hAo,lAo; TLV(ec,ao,out hAo,out lAo); string algoOid=Oid(Sub(ec,ao+hAo,lAo));
    int dOff=m0+hAi+lAi; int hD,lD; TLV(ec,dOff,out hD,out lD); byte[] digest=Sub(ec,dOff+hD,lD);
    IntPtr pg=IntPtr.Zero, sdig=IntPtr.Zero, hProv=IntPtr.Zero, hFileS=IntPtr.Zero;
    var ind=new IND();
    try{
      ind.dataOid=Marshal.StringToHGlobalAnsi(dataOid); ind.dataVal.cb=(uint)dataVal.Length; ind.dataVal.p=Marshal.AllocHGlobal(dataVal.Length); Marshal.Copy(dataVal,0,ind.dataVal.p,dataVal.Length); ind.algo.oid=Marshal.StringToHGlobalAnsi(algoOid); ind.digest.cb=(uint)digest.Length; ind.digest.p=Marshal.AllocHGlobal(digest.Length); Marshal.Copy(digest,0,ind.digest.p,digest.Length);
      Guid sip=Guid.Empty; CryptSIPRetrieveSubjectGuid(path,IntPtr.Zero,ref sip); var di=new DISP(); di.cbSize=(uint)Marshal.SizeOf(typeof(DISP)); if(CryptSIPLoad(ref sip,0,ref di)){
        var vf=(VerifyFn)Marshal.GetDelegateForFunctionPointer(di.pfVerify,typeof(VerifyFn));
        hFileS=CreateFile(path,GR,FSR,IntPtr.Zero,OE,0,IntPtr.Zero); CryptAcquireContext(ref hProv,null,null,24,0xF0000000);
        pg=Marshal.AllocHGlobal(16); Marshal.StructureToPtr(sip,pg,false);
        sdig=Marshal.StringToHGlobalAnsi(algoOid);
        var s=new SUBJ(); s.cbSize=(uint)Marshal.SizeOf(typeof(SUBJ)); s.pgType=pg; s.hFile=hFileS; s.file=path; s.enc=0x10001; s.hProv=hProv; s.dig.oid=sdig;
        contentOk = vf(ref s,ref ind)==0;
      }
    } finally {
      if(ind.dataOid!=IntPtr.Zero)Marshal.FreeHGlobal(ind.dataOid); if(ind.dataVal.p!=IntPtr.Zero)Marshal.FreeHGlobal(ind.dataVal.p); if(ind.algo.oid!=IntPtr.Zero)Marshal.FreeHGlobal(ind.algo.oid); if(ind.digest.p!=IntPtr.Zero)Marshal.FreeHGlobal(ind.digest.p);
      if(pg!=IntPtr.Zero)Marshal.FreeHGlobal(pg); if(sdig!=IntPtr.Zero)Marshal.FreeHGlobal(sdig);
      if(hProv!=IntPtr.Zero)CryptReleaseContext(hProv,0); if(hFileS!=IntPtr.Zero&&hFileS!=new IntPtr(-1))CloseHandle(hFileS);
    }
    return sigOk;
  }
  static string Tbs(X509Certificate2 c){ byte[] raw=c.RawData; int p=1; int l=raw[p++]; if(l>=0x80){int n=l&0x7F;l=0;for(int i=0;i<n;i++)l=(l<<8)|raw[p++];} int s=p; int q=s+1; int tl=raw[q++]; if(tl>=0x80){int n=tl&0x7F;tl=0;for(int i=0;i<n;i++)tl=(tl<<8)|raw[q++];} int tot=(q-s)+tl; byte[] t=new byte[tot]; Array.Copy(raw,s,t,0,tot); using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(t)).Replace("-","").ToLower(); }

  static string CN(X509Certificate2 c, bool issuer){ try{ return c.GetNameInfo(X509NameType.SimpleName, issuer); }catch{ return null; } }
  static string Sha256Cert(X509Certificate2 c){ using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(c.RawData)).Replace("-","").ToLower(); }
  static string Md5Cert(X509Certificate2 c){ using(var h=MD5.Create()) return BitConverter.ToString(h.ComputeHash(c.RawData)).Replace("-","").ToLower(); }
  // DER walk: collect GeneralName URI ([6], tag 0x86, IA5String) values by exact length; recurse into constructed nodes
  static void CollectUris(byte[] b, int o, int end, System.Collections.Generic.List<string> outv, int depth){ if(depth>24) return; int p=o; while(p+1<end){ int hl,ln,tag; try{ tag=TLV(b,p,out hl,out ln); }catch{ break; } int cs=p+hl; if(ln<0||cs+ln>end) break; if(tag==0x86){ string u=Encoding.ASCII.GetString(b,cs,ln).Trim(); if(u.Length>0&&!outv.Contains(u))outv.Add(u); } else if((tag&0x20)!=0){ CollectUris(b,cs,cs+ln,outv,depth+1); } p=cs+ln; } }
  static System.Collections.Generic.List<string> CdpUrls(X509Certificate2 c){ var r=new System.Collections.Generic.List<string>(); foreach(var ext in c.Extensions){ if(ext.Oid.Value=="2.5.29.31"){ try{ CollectUris(ext.RawData,0,ext.RawData.Length,r,0); }catch{} } } return r; }
  // AIA = SEQUENCE OF AccessDescription{ accessMethod OID, accessLocation GeneralName }; split caIssuers (..48.2) vs OCSP (..48.1)
  static void AiaUrls(X509Certificate2 c, System.Collections.Generic.List<string> ca, System.Collections.Generic.List<string> ocsp){ foreach(var ext in c.Extensions){ if(ext.Oid.Value!="1.3.6.1.5.5.7.1.1") continue; try{ byte[] raw=ext.RawData; int hl,ln; if(TLV(raw,0,out hl,out ln)!=0x30) continue; int p=hl,end=hl+ln; while(p+1<end){ int h2,l2; int t2=TLV(raw,p,out h2,out l2); int cs=p+h2; if(l2<0||cs+l2>end) break; if(t2==0x30){ int ip=cs,iend=cs+l2; string method=null,uri=null; while(ip+1<iend){ int h3,l3; int t3=TLV(raw,ip,out h3,out l3); int ccs=ip+h3; if(l3<0||ccs+l3>iend) break; if(t3==0x06) method=Oid(Sub(raw,ccs,l3)); else if(t3==0x86) uri=Encoding.ASCII.GetString(raw,ccs,l3).Trim(); ip=ccs+l3; } if(uri!=null&&uri.Length>0){ if(method=="1.3.6.1.5.5.7.48.2"){ if(!ca.Contains(uri))ca.Add(uri); } else if(method=="1.3.6.1.5.5.7.48.1"){ if(!ocsp.Contains(uri))ocsp.Add(uri); } } } p=cs+l2; } }catch{} } }
  static bool SelfIssued(X509Certificate2 c){ byte[] su=c.SubjectName.RawData, iss=c.IssuerName.RawData; if(su.Length!=iss.Length) return false; for(int k=0;k<su.Length;k++) if(su[k]!=iss[k]) return false; return true; }
  static bool IsTrustedRoot(X509Certificate2 c){ if(c==null) return false; foreach(var loc in new[]{StoreLocation.LocalMachine,StoreLocation.CurrentUser}){ try{ using(var st=new X509Store(StoreName.Root,loc)){ st.Open(OpenFlags.ReadOnly); if(st.Certificates.Find(X509FindType.FindByThumbprint,c.Thumbprint,false).Count>0) return true; } }catch{} } return false; }
  static string UrlArr(System.Collections.Generic.List<string> l){ var b=new StringBuilder("["); for(int i=0;i<l.Count;i++){ if(i>0)b.Append(","); b.Append(J(l[i])); } return b.Append("]").ToString(); }
  static string TbsAlg(X509Certificate2 c, string alg){ byte[] raw=c.RawData; int p=1; int l=raw[p++]; if(l>=0x80){int n=l&0x7F;l=0;for(int i=0;i<n;i++)l=(l<<8)|raw[p++];} int s=p; int q=s+1; int tl=raw[q++]; if(tl>=0x80){int n=tl&0x7F;tl=0;for(int i=0;i<n;i++)tl=(tl<<8)|raw[q++];} int tot=(q-s)+tl; byte[] t=new byte[tot]; Array.Copy(raw,s,t,0,tot); using(var h=HashAlgorithm.Create(alg)) return BitConverter.ToString(h.ComputeHash(t)).Replace("-","").ToLower(); }
  public static string CertJson(X509Certificate2 c){ if(c==null) return "null"; var eku=new System.Collections.Generic.List<string>(); bool cs=false; foreach(var e in c.Extensions){ var k=e as X509EnhancedKeyUsageExtension; if(k!=null){ foreach(var o in k.EnhancedKeyUsages){ eku.Add(o.Value); if(o.Value=="1.3.6.1.5.5.7.3.3") cs=true; } } }
    var sb=new StringBuilder("{"); sb.Append("\"subject\":").Append(J(c.Subject)).Append(",\"subject_cn\":").Append(J(CN(c,false))).Append(",\"issuer\":").Append(J(c.Issuer)).Append(",\"issuer_cn\":").Append(J(CN(c,true)));
    sb.Append(",\"serial_number\":").Append(J(c.SerialNumber)).Append(",\"thumbprint\":").Append(J(c.Thumbprint)).Append(",\"md5_fingerprint\":").Append(J(Md5Cert(c))).Append(",\"sha1_fingerprint\":").Append(J(c.Thumbprint.ToLower())).Append(",\"sha256_fingerprint\":").Append(J(Sha256Cert(c)));
    sb.Append(",\"tbs_sha1\":").Append(J(TbsAlg(c,"SHA1"))).Append(",\"tbs_sha256\":").Append(J(TbsAlg(c,"SHA256"))).Append(",\"not_before\":").Append(J(c.NotBefore.ToUniversalTime().ToString("o"))).Append(",\"not_after\":").Append(J(c.NotAfter.ToUniversalTime().ToString("o")));
    sb.Append(",\"eku\":["); for(int i=0;i<eku.Count;i++){ if(i>0)sb.Append(","); sb.Append(J(eku[i])); } sb.Append("],\"eku_codesigning\":").Append(cs?"true":"false"); sb.Append(",\"self_signed\":").Append((SelfIssued(c)&&!IsTrustedRoot(c))?"true":"false"); var _ca=new System.Collections.Generic.List<string>(); var _ocsp=new System.Collections.Generic.List<string>(); AiaUrls(c,_ca,_ocsp); sb.Append(",\"crl_urls\":").Append(UrlArr(CdpUrls(c))).Append(",\"ca_issuer_urls\":").Append(UrlArr(_ca)).Append(",\"ocsp_urls\":").Append(UrlArr(_ocsp)).Append("}"); return sb.ToString(); }
  public static bool EkuOkForCodeSign(X509Certificate2 c){ if(c==null) return false; bool hasEku=false; foreach(var e in c.Extensions){ var k=e as X509EnhancedKeyUsageExtension; if(k!=null){ hasEku=true; foreach(var oo in k.EnhancedKeyUsages) if(oo.Value=="1.3.6.1.5.5.7.3.3") return true; } } return !hasEku; }
  static bool TsaTrusted(X509Certificate2 tsa, X509Certificate2Collection extra){ if(tsa==null) return false; try{ using(var ch=new X509Chain()){ ch.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck; if(extra!=null) ch.ChainPolicy.ExtraStore.AddRange(extra); bool ok=ch.Build(tsa); bool ut=false; foreach(var st in ch.ChainStatus){ if((st.Status&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)ut=true; } return ok && !ut; } }catch{ return false; } }
  static bool IsOS(string sigType, X509Certificate2 signer){ if(signer==null) return false; return sigType=="Catalog" && (signer.Subject.Contains("Microsoft Windows")||signer.Subject.Contains("Microsoft Corporation")); }
  static X509Certificate2Collection embeddedCerts=null;
  static long maxBytes=500L*1024*1024;
  static System.Collections.Generic.Dictionary<string,string[]> gvTbs, gvThumb, gvSerial, gvHash;
  static void LoadGraveyard(string csv){ gvTbs=new System.Collections.Generic.Dictionary<string,string[]>(); gvThumb=new System.Collections.Generic.Dictionary<string,string[]>(); gvSerial=new System.Collections.Generic.Dictionary<string,string[]>(); gvHash=new System.Collections.Generic.Dictionary<string,string[]>();
    if(!File.Exists(csv)) return; string[] lines=File.ReadAllLines(csv); if(lines.Length<2) return; var hdr=SplitCsv(lines[0]);
    int iHash=Array.IndexOf(hdr,"Hash"),iSer=Array.IndexOf(hdr,"Serial"),iThumb=Array.IndexOf(hdr,"Thumbprint"),iTbs=Array.IndexOf(hdr,"TBS SHA256"),iMal=Array.IndexOf(hdr,"Malware"),iTyp=Array.IndexOf(hdr,"Malware Type");
    for(int li=1;li<lines.Length;li++){ var f=SplitCsv(lines[li]); string[] rec={ iMal>=0&&iMal<f.Length?f[iMal]:"", iTyp>=0&&iTyp<f.Length?f[iTyp]:"" };
      if(iTbs>=0&&iTbs<f.Length&&f[iTbs].Length>0) gvTbs[f[iTbs].ToLower()]=rec; if(iThumb>=0&&iThumb<f.Length&&f[iThumb].Length>0) gvThumb[f[iThumb].Replace(" ","").ToUpper()]=rec; if(iSer>=0&&iSer<f.Length&&f[iSer].Length>0) gvSerial[f[iSer].Replace(" ","").ToUpper()]=rec; if(iHash>=0&&iHash<f.Length&&f[iHash].Length>0) gvHash[f[iHash].ToLower()]=rec; } }
  static string[] SplitCsv(string line){ var o=new System.Collections.Generic.List<string>(); var cur=new StringBuilder(); bool q=false; foreach(char c in line){ if(c=='"') q=!q; else if(c==','&&!q){ o.Add(cur.ToString()); cur.Clear(); } else cur.Append(c); } o.Add(cur.ToString()); return o.ToArray(); }
  static string GraveyardJson(string thumb, string serial, string tbs, string fileSha){ if(gvTbs==null) return "{\"hit\":false}"; string[] r=null; string on=null;
    if(tbs!=null&&gvTbs.TryGetValue(tbs.ToLower(),out r)) on="cert_tbs_sha256"; else if(thumb!=null&&gvThumb.TryGetValue(thumb.Replace(" ","").ToUpper(),out r)) on="cert_thumbprint"; else if(serial!=null&&gvSerial.TryGetValue(serial.Replace(" ","").ToUpper(),out r)) on="cert_serial"; else if(fileSha!=null&&gvHash.TryGetValue(fileSha.ToLower(),out r)) on="file_sha256";
    if(r==null) return "{\"hit\":false}"; return "{\"hit\":true,\"matched_on\":"+J(on)+",\"malware\":"+J(r[0])+",\"malware_type\":"+J(r[1])+"}"; }


  static string[] PsStatus(string path){ try{
    var psi=new System.Diagnostics.ProcessStartInfo("powershell.exe","-NoProfile -ExecutionPolicy Bypass -Command \"$s=Get-AuthenticodeSignature -LiteralPath $env:VAL_PATH; $c=$s.SignerCertificate; [Console]::Out.Write($s.Status.ToString()+'|'+$(if($c){$c.Thumbprint}else{''}))\"");
    psi.UseShellExecute=false; psi.RedirectStandardOutput=true; psi.CreateNoWindow=true; psi.EnvironmentVariables["VAL_PATH"]=path;
    using(var p=System.Diagnostics.Process.Start(psi)){ var ot=p.StandardOutput.ReadToEndAsync(); if(!p.WaitForExit(15000)){ try{p.Kill();}catch{} return new[]{"UnknownError",""}; } string o=""; try{ o=ot.Result; }catch{} return o.Split('|'); }
  }catch{ return new[]{"UnknownError",""}; } }
  static string MapPs(string s){ switch(s){ case "Valid":return "Valid"; case "HashMismatch":return "HashMismatch"; case "NotSigned":return "NotSigned"; case "NotTrusted":return "UntrustedRoot"; case "UnknownError":return "UnknownError"; default:return s; } }


  static string RunCmd(string exe,string args){ try{ var psi=new System.Diagnostics.ProcessStartInfo(exe,args){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}; using(var p=System.Diagnostics.Process.Start(psi)){ string o=p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd(); p.WaitForExit(90000); return o.Replace("\r"," ").Replace("\n"," "); } }catch(Exception e){ return "ERR:"+e.Message; } }
  static int RunRc(string exe,string args){ try{ var psi=new System.Diagnostics.ProcessStartInfo(exe,args){UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true}; using(var p=System.Diagnostics.Process.Start(psi)){ p.StandardOutput.ReadToEnd(); p.StandardError.ReadToEnd(); p.WaitForExit(90000); return p.ExitCode; } }catch{ return -1; } }
  static string RefreshTrust(){
    var b=new StringBuilder("{");
    string crl=RunCmd("certutil.exe","-urlcache crl delete");
    string ocsp=RunCmd("certutil.exe","-urlcache ocsp delete");
    string tmp=System.IO.Path.GetTempPath()+"wuroots";
    try{ System.IO.Directory.CreateDirectory(tmp); }catch{}
    string roots=RunCmd("certutil.exe","-f -syncWithWU \""+tmp+"\"");
    string disSst=System.IO.Path.Combine(tmp,"disallowedcert.sst");
    bool disInstalled=false; int disCount=0;
    try{ if(System.IO.File.Exists(disSst)){ disInstalled = RunRc("certutil.exe","-addstore -f Disallowed \""+disSst+"\"")==0; } using(var ds=new X509Store(StoreName.Disallowed,StoreLocation.LocalMachine)){ ds.Open(OpenFlags.ReadOnly); disCount=ds.Certificates.Count; } }catch{}
    b.Append("\"crl_cache_cleared\":").Append(crl.ToLower().Contains("deleted")||crl.ToLower().Contains("command completed")?"true":"false");
    b.Append(",\"ocsp_cache_cleared\":").Append(ocsp.ToLower().Contains("deleted")||ocsp.ToLower().Contains("command completed")?"true":"false");
    b.Append(",\"roots_synced\":").Append(roots.ToLower().Contains("command completed")||roots.ToLower().Contains(".crt")?"true":"false");
    b.Append(",\"roots_detail\":").Append(J(roots.Length>120?roots.Substring(0,120):roots));
    b.Append(",\"disallowed_kill_list_installed\":").Append(disInstalled?"true":"false");
    b.Append(",\"disallowed_store_count\":").Append(disCount);
    return b.Append("}").ToString();
  }


  static System.Collections.Generic.SortedSet<string> harvestedCDP=new System.Collections.Generic.SortedSet<string>();
  static void HarvestCDP(X509Certificate2 c){ foreach(var ext in c.Extensions){ if(ext.Oid.Value=="2.5.29.31"||ext.Oid.Value=="1.3.6.1.5.5.7.1.1"){ try{ var us=new System.Collections.Generic.List<string>(); CollectUris(ext.RawData,0,ext.RawData.Length,us,0); foreach(var u in us) harvestedCDP.Add(u); }catch{} } } }
  static string WarmCache(string dir){ int n=0,certs=0; var files=Directory.Exists(dir)?Directory.GetFiles(dir):new string[]{dir};
    foreach(var f in files){ try{ X509Certificate2 signer; string st; X509Certificate2 tsa; DateTime? stm; VerifyBinary(f,out signer,out st,out tsa,out stm);
      if(signer==null){ byte[] der=ScriptPkcs7(f); if(der!=null){ try{ var cms=new SignedCms(); cms.Decode(der); signer=cms.SignerInfos[0].Certificate; }catch{} } }
      if(signer!=null){ var ch=new X509Chain(); ch.ChainPolicy.RevocationMode=X509RevocationMode.Online; ch.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch.Build(signer); foreach(var el in ch.ChainElements){ HarvestCDP(el.Certificate); certs++; } ch.Dispose(); n++; }
    }catch{} }
    var b=new StringBuilder("{\"warmed_files\":"+n+",\"chain_certs\":"+certs+",\"crl_ocsp_urls_cached\":["); bool fst=true; foreach(var u in harvestedCDP){ if(!fst)b.Append(","); b.Append(J(u)); fst=false; } return b.Append("]}").ToString();
  }

  static string J(string s){ if(s==null)return "null"; var b=new StringBuilder("\""); foreach(char ch in s){ if(ch=='\\')b.Append("\\\\"); else if(ch=='"')b.Append("\\\""); else if(ch<0x20||ch>0x7E)b.Append("\\u").Append(((int)ch).ToString("x4")); else b.Append(ch); } b.Append("\""); return b.ToString(); }
  static string Sha(string path){ using(var s=File.OpenRead(path)) using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLower(); }
  // Parse the PE security directory's WIN_CERTIFICATE PKCS#7 and return its embedded certs (for ExtraStore); null if none/not a PE
  static X509Certificate2Collection PeEmbeddedCerts(string path){ try{
    using(var fs=File.OpenRead(path)){
      byte[] h=new byte[0x400]; int n=fs.Read(h,0,h.Length); if(n<0x40) return null;
      int pe=BitConverter.ToInt32(h,0x3C); if(pe<0||pe+0x78>n) return null;
      if(h[pe]!=(byte)'P'||h[pe+1]!=(byte)'E') return null;
      int optHdr=pe+0x18; if(optHdr+2>n) return null; ushort magic=BitConverter.ToUInt16(h,optHdr);
      int ddOff=optHdr+(magic==0x20b?112:96); int secOff=ddOff+4*8; if(secOff+8>n) return null;
      int certVA=BitConverter.ToInt32(h,secOff); int certSize=BitConverter.ToInt32(h,secOff+4);
      if(certVA<=8||certSize<=8||(long)certVA+certSize>fs.Length) return null;
      fs.Seek(certVA,SeekOrigin.Begin); byte[] wc=new byte[8]; if(fs.Read(wc,0,8)<8) return null;
      int dwLength=BitConverter.ToInt32(wc,0); int blobLen=dwLength-8;
      if(blobLen<=0||blobLen>64*1024*1024||(long)certVA+8+blobLen>fs.Length) return null;
      byte[] pkcs7=new byte[blobLen]; int got=0; while(got<blobLen){ int r=fs.Read(pkcs7,got,blobLen-got); if(r<=0) break; got+=r; } if(got<blobLen) return null;
      var cms=new SignedCms(); cms.Decode(pkcs7); return cms.Certificates;
    } }catch{ return null; } }
  static string MapBin(int r){ uint u=(uint)r; if(r==0)return "Valid"; switch(u){ case 0x800B0100:return "NotSigned"; case 0x80096010:return "HashMismatch"; case 0x800B010C:return "Revoked"; case 0x800B0109:return "UntrustedRoot"; default:return "UnknownError"; } }
  static string ErrJson(string fileSha, string status, string error){ return "{\"file_sha256\":"+J(fileSha)+",\"status\":"+J(status)+",\"error\":"+J(error)+",\"signature_type\":\"None\",\"content_verified\":false,\"is_os_binary\":false,\"signer\":null,\"chain\":null,\"graveyard\":{\"hit\":false},\"timestamped\":false,\"sign_time\":null,\"sign_time_verified\":false,\"timestamper\":null,\"ms\":0}"; }

  public static void Main(string[] a){
    try{ System.AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", System.TimeSpan.FromSeconds(2)); }catch{}
    if(IntPtr.Size!=8) Console.Error.WriteLine("warning: validator assumes x86_64 P/Invoke layout; pointer size="+IntPtr.Size);
    try{ var _e=Environment.GetEnvironmentVariable("VALIDATOR_MAX_SIZE_MB"); long _m; if(_e!=null&&long.TryParse(_e,out _m)&&_m>0&&_m<=long.MaxValue/(1024L*1024L)) maxBytes=_m*1024L*1024L; }catch{}
    string path=null, gvCsv=null, rev="online", warmDir=null; int iters=1;
    for(int i=0;i<a.Length;i++){ if(a[i]=="--gv"&&i+1<a.Length){gvCsv=a[++i];} else if(a[i]=="--rev"&&i+1<a.Length){rev=a[++i];} else if(a[i]=="--iters"&&i+1<a.Length){iters=int.Parse(a[++i]);} else if(a[i]=="--refresh"){} else if(a[i]=="--warm-cache"&&i+1<a.Length){warmDir=a[++i];} else if(a[i]=="--max-size"&&i+1<a.Length){ long _mb; if(long.TryParse(a[++i],out _mb)&&_mb>0&&_mb<=long.MaxValue/(1024L*1024L)) maxBytes=_mb*1024L*1024L; } else if(a[i].StartsWith("--")){ Console.Error.WriteLine("warning: unknown flag "+a[i]); } else path=a[i]; }
    if(rev!="online"&&rev!="offline"&&rev!="none"){ Console.Error.WriteLine("warning: invalid --rev \""+rev+"\", using online"); rev="online"; }
    string scriptMode="ps"; for(int i=0;i<a.Length;i++){ if(a[i]=="--scripts"&&i+1<a.Length) scriptMode=a[i+1]; }
    bool refresh=false; foreach(var x in a) if(x=="--refresh") refresh=true;
    if(refresh){ string rr=RefreshTrust(); if(path==null){ Console.WriteLine(rr); return; } Console.Error.WriteLine("refresh: "+rr); }
    if(gvCsv!=null) LoadGraveyard(gvCsv);
    if(warmDir!=null){ Console.WriteLine(WarmCache(warmDir)); return; }
    if(path!=null && path.StartsWith("\\\\.\\")){ Console.WriteLine(ErrJson(null,"UnknownError","device path rejected")); return; }
    if(path!=null){ try{ if(new FileInfo(path).Length > maxBytes){ Console.WriteLine(ErrJson(null,"UnknownError","file too large")); return; } }catch{} }
    if(path!=null && path.ToLower().EndsWith(".rdp")){ try{ Console.WriteLine(RdpVal.Validate(path, rev)); }catch(OutOfMemoryException){ throw; }catch(Exception _rex){ try{Console.Error.WriteLine(_rex.ToString());}catch{} Console.WriteLine(ErrJson(null,"UnknownError",_rex.GetType().Name)); } return; }
    var sw=new Stopwatch();
    for(int it=0;it<iters;it++){ sw.Restart();
      embeddedCerts=null;
      string sha=null; try{ sha=Sha(path); }catch{}
      try{
      X509Certificate2 signer=null, tsa=null; DateTime? signTime=null; string sigType="None"; string status; string psThumb=null; string diag=null; bool stVerified=false;
      int res=VerifyBinary(path,out signer,out sigType,out tsa,out signTime);
      if(signer!=null) embeddedCerts=PeEmbeddedCerts(path);
      bool contentOk=true;
      if((uint)res==0x800B0100){ byte[] der=ScriptPkcs7(path);
        if(der!=null){ bool sigOk=VerifyScript(path,der,out signer,out contentOk,out tsa,out signTime); sigType="Script";
          if(scriptMode=="ps"){ var pr=PsStatus(path); status=MapPs(pr[0]); contentOk=(status!="HashMismatch"); if(status=="NotSigned"){ signer=null; tsa=null; sigType="None"; } }
          else { if(!sigOk||!contentOk) status="HashMismatch"; else status="__chain__"; } }
        else { if(scriptMode=="ps"){ var pr=PsStatus(path); status=MapPs(pr[0]); if(status!="NotSigned"&&pr.Length>1&&pr[1].Length>0) psThumb=pr[1]; } else status="NotSigned"; }
      } else { status=MapBin(res); if(status=="UnknownError"||status=="HashMismatch") diag="wintrust=0x"+((uint)res).ToString("X8"); }
      var b=new StringBuilder(); b.Append("{\"file_sha256\":").Append(J(sha));
      string chainJson="null";
      if(signer!=null){
        var ch=new X509Chain(); ch.ChainPolicy.RevocationMode=(rev=="offline"?X509RevocationMode.Offline:rev=="none"?X509RevocationMode.NoCheck:X509RevocationMode.Online); ch.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch.ChainPolicy.UrlRetrievalTimeout=TimeSpan.FromSeconds(15); if(embeddedCerts!=null) ch.ChainPolicy.ExtraStore.AddRange(embeddedCerts);
        stVerified = (sigType=="Script") ? TsaTrusted(tsa, embeddedCerts) : (tsa!=null); try{ ch.ChainPolicy.VerificationTime = (signTime.HasValue && (sigType!="Script" || stVerified)) ? signTime.Value : (tsa!=null ? signer.NotBefore.AddMinutes(1) : DateTime.Now); }catch{}
        bool ok=ch.Build(signer); bool revoked=false,untrusted=false,nottime=false,revunk=false,distrusted=false;
        foreach(var s2 in ch.ChainStatus){ var f=s2.Status; if(f==X509ChainStatusFlags.Revoked)revoked=true; if((f&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)untrusted=true; if((f&X509ChainStatusFlags.NotTimeValid)!=0)nottime=true; if((f&(X509ChainStatusFlags.RevocationStatusUnknown|X509ChainStatusFlags.OfflineRevocation))!=0)revunk=true; if((f&X509ChainStatusFlags.ExplicitDistrust)!=0)distrusted=true; }
        if(status=="__chain__"){ status = (!untrusted&&!revoked&&EkuOkForCodeSign(signer))?"Valid":(revoked?"Revoked":"UnknownError"); }
        else if(sigType=="Script" && status=="Valid" && (untrusted||revoked)){ status = revoked?"Revoked":"UnknownError"; }
        if(revoked && status!="HashMismatch" && status!="NotSigned") status="Revoked";
        if(distrusted && status!="HashMismatch" && status!="NotSigned") status="Distrusted";
        var celems=new System.Collections.Generic.List<string>(); foreach(var el in ch.ChainElements) celems.Add(CertJson(el.Certificate));
        chainJson="{\"chain_builds\":"+(ok?"true":"false")+",\"chains_to_trusted_root\":"+(!untrusted?"true":"false")+",\"revoked\":"+(revoked?"true":"false")+",\"explicit_distrust\":"+(distrusted?"true":"false")+",\"revocation_checked\":"+(revoked||!revunk?"\"online\"":"\"unknown\"")+",\"valid_at_sign_time\":"+(!untrusted&&!revoked&&!nottime&&!distrusted?"true":"false")+",\"chain_length\":"+ch.ChainElements.Count+",\"chain\":["+string.Join(",",celems)+"]}"; ch.Dispose();
      }
      if(status=="__chain__") status="UnknownError";
      if(signer==null && status!="Valid") contentOk=false;
      b.Append(",\"status\":").Append(J(status)).Append(",\"signature_type\":").Append(J(sigType)).Append(",\"content_verified\":").Append(contentOk?"true":"false"); if(diag!=null) b.Append(",\"error\":").Append(J(diag));
      b.Append(",\"is_os_binary\":").Append(IsOS(sigType,signer)?"true":"false"); b.Append(",\"signer\":").Append(CertJson(signer)); b.Append(",\"chain\":").Append(chainJson); b.Append(",\"graveyard\":").Append(GraveyardJson(signer!=null?signer.Thumbprint:psThumb, signer!=null?signer.SerialNumber:null, signer!=null?TbsAlg(signer,"SHA256"):null, sha)); b.Append(",\"timestamped\":").Append(tsa!=null?"true":"false"); b.Append(",\"sign_time\":").Append(signTime.HasValue?J(signTime.Value.ToString("o")):"null"); b.Append(",\"sign_time_verified\":").Append((signTime.HasValue&&stVerified)?"true":"false"); b.Append(",\"timestamper\":").Append(CertJson(tsa));
      b.Append(",\"ms\":").Append(sw.ElapsedMilliseconds).Append("}");
      Console.WriteLine(b.ToString());
      signer?.Dispose(); tsa?.Dispose();
      }catch(OutOfMemoryException){ throw; }catch(Exception _ex){ try{Console.Error.WriteLine(_ex.ToString());}catch{} Console.WriteLine(ErrJson(sha,"UnknownError",_ex.GetType().Name)); }
    }
  }
}
