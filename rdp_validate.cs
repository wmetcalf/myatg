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
    string text=File.ReadAllText(path); // auto-detects UTF-16 BOM
    var sigM=Regex.Match(text, @"signature:s:([^\r\n]*)", RegexOptions.IgnoreCase);
    var scopeM=Regex.Match(text, @"signscope:s:([^\r\n]*)", RegexOptions.IgnoreCase);
    var sb=new StringBuilder("{\"file\":"+J(Path.GetFileName(path)));
    if(!sigM.Success){ return sb.Append(",\"status\":\"NotSigned\"}").ToString(); }
    string b64=Regex.Replace(sigM.Groups[1].Value,@"\s","");
    string status; X509Certificate2 signer=null; bool sigOk=false; var chainInfo="null";
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
      try{ var scms=new SignedCms(new ContentInfo(new Oid("1.2.840.113549.1.7.1"),msgblob),true); scms.Decode(pkcs7); scms.CheckSignature(true); sigOk=true; }catch{ sigOk=false; }
      DateTime? signTime=null;
      try{ foreach(var at in cms.SignerInfos[0].SignedAttributes){ if(at.Oid.Value=="1.2.840.113549.1.9.5"&&at.Values.Count>0){ var t=new Pkcs9SigningTime(at.Values[0].RawData); signTime=t.SigningTime.ToUniversalTime(); } } }catch{}
      var ch=new X509Chain(); ch.ChainPolicy.RevocationMode=rm; ch.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch.ChainPolicy.UrlRetrievalTimeout=TimeSpan.FromSeconds(15); ch.ChainPolicy.ExtraStore.AddRange(cms.Certificates);
      bool built=ch.Build(signer); bool untrusted=false,revoked=false,notTime=false,revUnk=false,distrusted=false;
      foreach(var st in ch.ChainStatus){ var f=st.Status; if((f&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)untrusted=true; if(f==X509ChainStatusFlags.Revoked)revoked=true; if((f&X509ChainStatusFlags.NotTimeValid)!=0)notTime=true; if((f&(X509ChainStatusFlags.RevocationStatusUnknown|X509ChainStatusFlags.OfflineRevocation))!=0)revUnk=true; if((f&X509ChainStatusFlags.ExplicitDistrust)!=0)distrusted=true; }
      DateTime now=DateTime.UtcNow; bool expired=now>signer.NotAfter.ToUniversalTime(); bool notYet=now<signer.NotBefore.ToUniversalTime();
      bool validAtSign=false; if(signTime.HasValue){ var ch2=new X509Chain(); ch2.ChainPolicy.RevocationMode=rm; ch2.ChainPolicy.RevocationFlag=X509RevocationFlag.EntireChain; ch2.ChainPolicy.VerificationTime=signTime.Value; ch2.ChainPolicy.ExtraStore.AddRange(cms.Certificates); ch2.Build(signer); bool u2=false,r2=false,t2=false,d2=false; foreach(var st in ch2.ChainStatus){ var f=st.Status; if((f&(X509ChainStatusFlags.UntrustedRoot|X509ChainStatusFlags.PartialChain))!=0)u2=true; if(f==X509ChainStatusFlags.Revoked)r2=true; if((f&X509ChainStatusFlags.NotTimeValid)!=0)t2=true; if((f&X509ChainStatusFlags.ExplicitDistrust)!=0)d2=true; } validAtSign=!u2&&!r2&&!t2&&!d2; ch2.Dispose(); }
      var elems=new List<string>(); foreach(var el in ch.ChainElements){ elems.Add(Validator.CertJson(el.Certificate)); }
      chainInfo="{\"signature_valid\":"+(sigOk?"true":"false")+",\"chains_to_trusted_root\":"+(!untrusted?"true":"false")+",\"revoked\":"+(revoked?"true":"false")+",\"explicit_distrust\":"+(distrusted?"true":"false")+",\"revocation_checked\":"+((revoked||!revUnk)?"\"online\"":"\"unknown\"")+",\"not_before\":"+J(signer.NotBefore.ToUniversalTime().ToString("o"))+",\"not_after\":"+J(signer.NotAfter.ToUniversalTime().ToString("o"))+",\"expired_now\":"+(expired?"true":"false")+",\"not_yet_valid\":"+(notYet?"true":"false")+",\"valid_now\":"+((built&&!revoked&&!notTime&&!untrusted&&!distrusted)?"true":"false")+",\"sign_time\":"+(signTime.HasValue?J(signTime.Value.ToString("o")):"null")+",\"sign_time_verified\":false,\"valid_at_sign_time\":"+(validAtSign?"true":"false")+",\"chain_length\":"+ch.ChainElements.Count+",\"chain\":["+string.Join(",",elems)+"]}"; ch.Dispose();
      status = !sigOk?"HashMismatch":(distrusted?"Distrusted":(revoked?"Revoked":(expired?"Expired":(notYet?"NotYetValid":(untrusted?"UntrustedRoot":((built&&!notTime&&Validator.EkuOkForCodeSign(signer))?"Valid":"UnknownError"))))));
    }catch(Exception e){ status="UnknownError"; try{Console.Error.WriteLine(e.ToString());}catch{} sb.Append(",\"error\":"+J(e.GetType().Name)); }
    sb.Append(",\"status\":"+J(status)+",\"signature_type\":\"RDP\"");
    if(signer!=null) sb.Append(",\"signer\":"+Validator.CertJson(signer));
    sb.Append(",\"chain\":"+chainInfo);
    // signscope coverage: settings present in file but NOT signed
    var signedScope=new HashSet<string>((scopeM.Success?scopeM.Groups[1].Value:"").Split(',').Select(x=>x.Trim().ToLower()));
    var fileKeys=new List<string>(); var unsignedDanger=new List<string>();
    foreach(Match m in Regex.Matches(text, @"(?im)^([a-z][a-z0-9 ]*?):[sib]:")){
      string k=m.Groups[1].Value.Trim().ToLower();
      if(k=="signature"||k=="signscope") continue;
      if(!fileKeys.Contains(k)) fileKeys.Add(k);
      if(!signedScope.Contains(k) && DANGEROUS.Contains(k) && !unsignedDanger.Contains(k)) unsignedDanger.Add(k);
    }
    int unsignedCount=fileKeys.Count(k=>!signedScope.Contains(k));
    sb.Append(",\"signscope_count\":"+signedScope.Count(x=>x.Length>0)+",\"total_settings\":"+fileKeys.Count+",\"unsigned_settings\":"+unsignedCount);
    sb.Append(",\"unsigned_dangerous\":["+string.Join(",",unsignedDanger.Select(J))+"]");
    return sb.Append("}").ToString();
  }
}
