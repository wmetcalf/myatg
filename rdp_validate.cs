using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
public class RdpVal {
  static readonly string[] DANGEROUS = { "drivestoredirect","redirectclipboard","redirectprinters","redirectcomports","redirectsmartcards","redirectdrives","redirectposdevices","remoteapplicationprogram","remoteapplicationcmdline","alternate shell","shell working directory","kdcproxyname","gatewayhostname","gatewaycredssource","gatewayprofileusagemethod","promptcredentialonce","enablecredsspsupport","authentication level","prompt for credentials","use redirection server name" };
  static string J(string s){ if(s==null)return "null"; var b=new StringBuilder("\""); foreach(char c in s){ if(c=='\\')b.Append("\\\\"); else if(c=='"')b.Append("\\\""); else if(c<0x20||c>0x7E)b.Append("\\u").Append(((int)c).ToString("x4")); else b.Append(c);} b.Append("\""); return b.ToString(); }
  public static string Validate(string path, string rev){
    X509RevocationMode rm = rev=="offline"?X509RevocationMode.Offline : rev=="none"?X509RevocationMode.NoCheck : X509RevocationMode.Online;
    // Format-specific cap well below the generic maxBytes: real .rdp files are a few KB, so an
    // 8 MB ceiling blocks a hostile multi-hundred-MB "RDP" from amplifying memory (whole-file read +
    // base64 signature decode + pkcs7 buffer) and OOM-crashing the persistent service.
    // Hash before the size guard: Validator.Sha streams, so it is memory-bounded and the guard's
    // amplification rationale never covered it. Without this an oversized known-bad sample reports
    // graveyard.hit:false purely because we declined to hash it.
    // Oversized files are hashed by streaming (memory-bounded) purely so the graveyard lookup
    // below can still run; everything under the guard is read ONCE into rawBytes and both the
    // hash and the parsed text are derived from that single buffer, so file_sha256 and the
    // signature analysis always describe the same snapshot.
    string oshaEarly=null;
    try{ if(new FileInfo(path).Length > 8L*1024*1024) oshaEarly=Validator.Sha(path); }catch{}
    try{ if(new FileInfo(path).Length > 8L*1024*1024) return "{\"file\":"+J(Path.GetFileName(path))+",\"file_sha256\":"+J(oshaEarly)+",\"status\":\"UnknownError\",\"signature_type\":\"RDP\",\"error\":\"rdp file too large\",\"content_verified\":false,\"signer\":null,\"chain\":null,\"graveyard\":"+Validator.GraveyardJson(null,null,null,oshaEarly)+"}"; }catch{}
    byte[] rawBytes=File.ReadAllBytes(path);
    string text; using(var _ms=new MemoryStream(rawBytes)) using(var _sr=new StreamReader(_ms,Encoding.UTF8,true)) text=_sr.ReadToEnd();  // same BOM auto-detection as ReadAllText
    using(var _h=System.Security.Cryptography.SHA256.Create()) oshaEarly=BitConverter.ToString(_h.ComputeHash(rawBytes)).Replace("-","").ToLowerInvariant();
    var sigM=Regex.Match(text, @"signature:s:([^\r\n]*)", RegexOptions.IgnoreCase);
    var scopeM=Regex.Match(text, @"signscope:s:([^\r\n]*)", RegexOptions.IgnoreCase);
    string fsha=oshaEarly;
    var sb=new StringBuilder("{\"file\":"+J(Path.GetFileName(path))+",\"file_sha256\":"+J(fsha));
    // GraveyardJson matches on file_sha256 alone, so an UNSIGNED .rdp whose hash is in the CSV
    // must still be looked up -- hard-coding hit:false here would silently drop exactly the
    // known-bad files this field exists to surface, which is the omission this change fixes.
    if(!sigM.Success){ return sb.Append(",\"status\":\"NotSigned\",\"signature_type\":\"None\",\"content_verified\":false,\"signer\":null,\"chain\":null,\"graveyard\":"+Validator.GraveyardJson(null,null,null,fsha)+"}").ToString(); }
    string b64=Regex.Replace(sigM.Groups[1].Value,@"\s","");
    string status; X509Certificate2 signer=null; bool sigOk=false; bool contentSigOk=false; var chainInfo="null";
    // Same exception-safety contract as myatg.cs ValidateFileLocked: every unmanaged handle opened
    // here is released on ANY exit path -- including a throw in the JSON assembly below the catch,
    // which sits outside the inner guard and used to skip disposal entirely.
    // extra is materialised once and fed to BOTH chains: cms.Certificates is a getter that rebuilds
    // the whole bag (new X509Certificate2 per cert) on every access, so reading it twice opened a
    // second full copy for no gain.
    X509Chain ch=null, ch2=null; X509Certificate2Collection extra=null;
    try{
    try{
      byte[] blob=Convert.FromBase64String(b64);
      if(blob.Length<12) throw new Exception("rdp sig blob too short");
      int size=BitConverter.ToInt32(blob,8);
      if(size<0 || (long)size>blob.Length-12L) throw new Exception("rdp sig size out of range");
      byte[] pkcs7=new byte[size]; Array.Copy(blob,12,pkcs7,0,size);
      var cms=new SignedCms(); cms.Decode(pkcs7);
      signer=cms.SignerInfos[0].Certificate;
      // reconstruct canonical signed content (nfedera format) and verify detached signature
      var bykey=new Dictionary<string,string>();
      foreach(Match mm in Regex.Matches(text.Replace("\r",""), @"(?im)^([a-z][a-z0-9 ]*?):[sib]:[^\n]*")){ string ln=mm.Value.Trim(); string kk=Regex.Match(ln,@"^([^:]+):").Groups[1].Value.Trim().ToLower(); if(!bykey.ContainsKey(kk)) bykey[kk]=ln; }
      var signnames=(scopeM.Success?scopeM.Groups[1].Value:"").Split(',').Select(x=>x.Trim()).Where(x=>x.Length>0).ToList();
      var signlines=new List<string>(); foreach(var nm in signnames){ if(bykey.ContainsKey(nm.ToLower())) signlines.Add(bykey[nm.ToLower()]); }
      string msgtext=string.Join("\r\n",signlines)+"\r\n"+"signscope:s:"+string.Join(",",signnames)+"\r\n"+"\u0000";
      byte[] msgblob=Encoding.Unicode.GetBytes(msgtext);
      // Two distinct facts. CheckSignature(true) skips CHAIN validation but still verifies every
      // signer INCLUDING countersigners, so a corrupt timestamp countersignature would otherwise be
      // reported as a content digest failure -- the same conflation fixed on the PE side for
      // TRUST_E_TIME_STAMP. contentSigOk is the primary signer's signature over the reconstructed
      // content and is what content_verified reports; sigOk stays the whole-message result.
      try{ var scms=new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.7.1"),msgblob),true); scms.Decode(pkcs7);
           try{ scms.SignerInfos[0].CheckSignature(true); contentSigOk=true; }catch{ contentSigOk=false; }
           scms.CheckSignature(true); sigOk=true; }catch{ sigOk=false; }
      DateTime? signTime=null;
      try{ foreach(var at in cms.SignerInfos[0].SignedAttributes){ if(at.Oid.Value=="1.2.840.113549.1.9.5"&&at.Values.Count>0){ var t=new Pkcs9SigningTime(at.Values[0].RawData); signTime=t.SigningTime.ToUniversalTime(); } } }catch{}
      ch=new X509Chain(); ch.ChainPolicy.RevocationMode=rm; ch.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch.ChainPolicy.UrlRetrievalTimeout=TimeSpan.FromSeconds(15); extra=cms.Certificates; ch.ChainPolicy.ExtraStore.AddRange(extra);
      bool built=ch.Build(signer); bool untrusted=false,revoked=false,notTime=false,revUnk=false,distrusted=false;
      foreach(var st in ch.ChainStatus){ var f=st.Status; if((f&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)untrusted=true; if(f==X509ChainStatusFlags.Revoked)revoked=true; if((f&X509ChainStatusFlags.NotTimeValid)!=0)notTime=true; if((f&(X509ChainStatusFlags.RevocationStatusUnknown|X509ChainStatusFlags.OfflineRevocation))!=0)revUnk=true; if((f&X509ChainStatusFlags.ExplicitDistrust)!=0)distrusted=true; }
      DateTime now=DateTime.UtcNow; bool expired=now>signer.NotAfter.ToUniversalTime(); bool notYet=now<signer.NotBefore.ToUniversalTime();
      bool validAtSign=false; if(signTime.HasValue){ ch2=new X509Chain(); ch2.ChainPolicy.RevocationMode=rm; ch2.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch2.ChainPolicy.VerificationTime=signTime.Value; ch2.ChainPolicy.ExtraStore.AddRange(extra); ch2.Build(signer); bool u2=false,r2=false,t2=false,d2=false; foreach(var st in ch2.ChainStatus){ var f=st.Status; if((f&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)u2=true; if(f==X509ChainStatusFlags.Revoked)r2=true; if((f&X509ChainStatusFlags.NotTimeValid)!=0)t2=true; if((f&X509ChainStatusFlags.ExplicitDistrust)!=0)d2=true; } validAtSign=!u2&&!r2&&!t2&&!d2; }
      var elems=new List<string>(); foreach(var el in ch.ChainElements){ elems.Add(Validator.CertJson(el.Certificate)); }
      chainInfo="{\"signature_valid\":"+(sigOk?"true":"false")+",\"chains_to_trusted_root\":"+(!untrusted?"true":"false")+",\"revoked\":"+(revoked?"true":"false")+",\"explicit_distrust\":"+(distrusted?"true":"false")+",\"revocation_checked\":"+(rev=="none"?"\"none\"":((revoked||!revUnk)?(rev=="offline"?"\"offline\"":"\"online\""):"\"unknown\""))+",\"not_before\":"+J(signer.NotBefore.ToUniversalTime().ToString("o"))+",\"not_after\":"+J(signer.NotAfter.ToUniversalTime().ToString("o"))+",\"expired_now\":"+(expired?"true":"false")+",\"not_yet_valid\":"+(notYet?"true":"false")+",\"valid_now\":"+((built&&!revoked&&!notTime&&!untrusted&&!distrusted)?"true":"false")+",\"sign_time\":"+(signTime.HasValue?J(signTime.Value.ToString("o")):"null")+",\"sign_time_verified\":false,\"valid_at_sign_time\":"+(validAtSign?"true":"false")+",\"chain_length\":"+ch.ChainElements.Count+",\"chain\":["+string.Join(",",elems)+"]}";
      // HashMismatch must mean the CONTENT digest failed. sigOk also covers countersignatures,
      // so keying status off it reported a bad timestamp as content tampering -- and, now that
      // content_verified is derived separately, produced status=HashMismatch beside
      // content_verified=true. Key it off the content signature; the whole-message result is
      // still reported as chain.signature_valid.
      status = !contentSigOk?"HashMismatch":(distrusted?"Distrusted":(revoked?"Revoked":(expired?"Expired":(notYet?"NotYetValid":(untrusted?"UntrustedRoot":((built&&!notTime&&Validator.EkuOkForCodeSign(signer))?"Valid":"UnknownError"))))));
    }catch(Exception e){ status="UnknownError"; try{Console.Error.WriteLine(e.ToString());}catch{} sb.Append(",\"error\":"+J(e.GetType().Name)); }
    // signscope coverage: settings present in file but NOT signed
    var signedScope=new HashSet<string>((scopeM.Success?scopeM.Groups[1].Value:"").Split(',').Select(x=>x.Trim().ToLower()));
    // Duplicate keys: signature reconstruction is first-wins, but mstsc.exe parses last-wins, so an
    // appended duplicate of a *signed* setting can carry a different (unsigned-effective) value that
    // still passes signature checks. We keep first-wins (it matches the signature) but surface every
    // duplicated key so a consumer can catch the shadowing — and flag a duplicated DANGEROUS key.
    var fileKeys=new List<string>(); var unsignedDanger=new List<string>(); var dupKeys=new List<string>();
    foreach(Match m in Regex.Matches(text, @"(?im)^([a-z][a-z0-9 ]*?):[sib]:")){
      string k=m.Groups[1].Value.Trim().ToLower();
      if(k=="signature"||k=="signscope") continue;
      if(!fileKeys.Contains(k)) fileKeys.Add(k); else if(!dupKeys.Contains(k)) dupKeys.Add(k);
      if(!signedScope.Contains(k) && DANGEROUS.Contains(k) && !unsignedDanger.Contains(k)) unsignedDanger.Add(k);
    }
    // a duplicated dangerous key is unsigned-effective under last-wins even if its first copy was signed
    foreach(var dk in dupKeys){ if(DANGEROUS.Contains(dk) && !unsignedDanger.Contains(dk)) unsignedDanger.Add(dk); }
    int unsignedCount=fileKeys.Count(k=>!signedScope.Contains(k));
    // For RDP, "content_verified" cannot just be sigOk. Reconstruction is FIRST-wins but mstsc.exe
    // parses LAST-wins (see the note above), so an appended duplicate of a signed setting keeps the
    // signature valid while changing what actually executes. Reporting true there would tell a
    // consumer the effective content matches what was signed when it demonstrably does not.
    bool shadowedSigned = dupKeys.Any(k => signedScope.Contains(k));
    bool contentEffective = contentSigOk && !shadowedSigned;
    sb.Append(",\"status\":"+J(status)+",\"signature_type\":\"RDP\"");
    // Same question as the other paths -- does the content match what was signed -- over a
    // different subject: for RDP the signed content is the canonical settings text named by
    // signscope, not the raw file bytes. sigOk alone is not enough; see shadowedSigned above.
    sb.Append(",\"content_verified\":"+(contentEffective?"true":"false"));
    sb.Append(",\"graveyard\":"+Validator.GraveyardJson(signer!=null?signer.Thumbprint:null, signer!=null?signer.SerialNumber:null, signer!=null?Validator.TbsAlg(signer,"SHA256"):null, fsha));
    if(signer!=null) sb.Append(",\"signer\":"+Validator.CertJson(signer));
    sb.Append(",\"chain\":"+chainInfo);
    sb.Append(",\"signscope_count\":"+signedScope.Count(x=>x.Length>0)+",\"total_settings\":"+fileKeys.Count+",\"unsigned_settings\":"+unsignedCount);
    sb.Append(",\"unsigned_dangerous\":["+string.Join(",",unsignedDanger.Select(J))+"]");
    sb.Append(",\"duplicate_settings\":["+string.Join(",",dupKeys.Select(J))+"]");
    return sb.Append("}").ToString();
    } finally {
      // SignerInfos[0].Certificate and every ExtraStore bag entry wrap an unmanaged handle, and each
      // chain holds a CERT_CHAIN_CONTEXT. Chains go first so nothing is disposed out from under them.
      if(ch!=null) ch.Dispose(); if(ch2!=null) ch2.Dispose();
      if(extra!=null){ foreach(X509Certificate2 _c in extra) _c.Dispose(); }
      if(signer!=null) signer.Dispose();
    }
  }
}
