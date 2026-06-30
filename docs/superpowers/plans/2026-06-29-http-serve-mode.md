# myatg HTTP serve mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an HTTP front end to myatg so a host can POST file bytes to a local, loopback-only endpoint and get back the existing JSON verdict, deployable as a least-privilege Windows service.

**Architecture:** A new `public partial class Validator` spread across `http_serve.cs` and `service.cs` reuses the existing private `ValidateFile(...)` core. The HTTP layer is the in-box, kernel-hardened `System.Net.HttpListener` (http.sys). Three additive run modes — `--serve-http` (console), `--service` (SCM entry), `--install-service`/`--uninstall-service` (one-time elevated setup) — sit alongside the unchanged one-shot path and stdin `--serve` (PR #2).

**Tech Stack:** C# (.NET Framework ≥4.5), in-box `csc` v4.0.30319, `System.Net.HttpListener`, `System.ServiceProcess.ServiceBase`, `sc.exe` + `netsh http` for service/urlacl setup.

**Spec:** `docs/superpowers/specs/2026-06-29-http-serve-design.md`

## Global Constraints

- **Windows-only runtime.** Validation uses WinVerifyTrust/X509Chain P/Invoke; tests run on Windows (local PowerShell or GitHub `windows-latest` CI), not on Linux. A non-Windows implementer relies on CI for the run/verify steps.
- **C# 5 syntax only.** The in-box `csc` v4.0.30319 rejects C# 6+: no null-conditional `?.`, no string interpolation `$"..."`, no expression-bodied members `=>`, no `nameof`. Use string concatenation. (The other branch already hit the `?.` rejection.)
- **Reuse the core.** All modes call `Validator.ValidateFile(path, rev, scriptMode)`; the verdict JSON schema does not change. Verdicts must stay byte-identical across one-shot / stdin / HTTP.
- **New code is `public partial class Validator`** so it can call the private static `ValidateFile`, `ErrJson`, and field `maxBytes` (in `myatg.cs`).
- **Defaults:** bind `127.0.0.1`, port `8137`, max-concurrency hardcoded `4`, urlacl via `netsh`, service account `NT SERVICE\myatg`.
- **Security:** loopback bind needs no token; a non-loopback `--bind` without `--token` refuses to start unless `--allow-insecure`.
- **Additive only:** do not modify the one-shot path or the stdin `--serve` loop behavior.

---

## File Structure

- **Modify `myatg.cs`** — change `public class Validator` → `public partial class Validator` (line 10); add HTTP/service flag parsing and dispatch in `Main` (around lines 216–235).
- **Create `http_serve.cs`** — `ServeOpts` options class; `ServeHttp`, `StopHttp`, request routing/auth/size-cap helpers. One responsibility: HTTP transport over the validate core.
- **Create `service.cs`** — `MyatgService : ServiceBase` (OnStart/OnStop) plus `InstallService`/`UninstallService` helpers. One responsibility: Windows service lifecycle + setup.
- **Modify `build.cmd`** — add new source files and `/r:System.ServiceProcess.dll`.
- **Modify `.github/workflows/ci.yml`** — add new files to the compile step and add HTTP/service smoke steps.
- **Modify `README.md`** — document the HTTP API, flags, and service install.

---

## Task 1: HTTP scaffolding + `/healthz` console server

**Files:**
- Modify: `myatg.cs:10` (class → partial), `myatg.cs:216-235` (flags + dispatch)
- Create: `http_serve.cs`
- Modify: `build.cmd:9`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing new.
- Produces: `Validator.ServeOpts` (fields `Bind`, `Port`, `Token`, `AllowInsecure`, `Rev`, `Scripts`, `MaxConcurrency`); `internal static int Validator.ServeHttp(ServeOpts)`; `internal static void Validator.StopHttp()`; `internal static bool Validator.IsLoopback(string)`; the HTTP loop with `GET /healthz` → `{"ok":true}`.

- [ ] **Step 1: Add the failing CI smoke step**

In `.github/workflows/ci.yml`, after the existing `--serve` smoke step (line 36), add:

```yaml
      - name: Smoke — --serve-http /healthz
        shell: pwsh
        run: |
          $p = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--port','8137' -PassThru
          Start-Sleep -Seconds 2
          try {
            $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8137/healthz' -TimeoutSec 5
            if (-not $r.ok) { Write-Error 'healthz not ok'; exit 1 }
            Write-Host 'healthz ok'
          } finally {
            Stop-Process -Id $p.Id -Force
          }
```

- [ ] **Step 2: Run the smoke to verify it fails**

Run (Windows/CI): build, then the step above.
Expected: FAIL — `--serve-http` is an unknown flag (process exits, `/healthz` connection refused).

- [ ] **Step 3: Make `Validator` partial**

In `myatg.cs` line 10, change:

```csharp
public class Validator {
```
to:
```csharp
public partial class Validator {
```

- [ ] **Step 4: Create `http_serve.cs` with the server loop and `/healthz`**

```csharp
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
}
```

- [ ] **Step 5: Parse the new flags and dispatch in `Main`**

In `myatg.cs`, extend the arg loop at line 217 to capture the new flags. Add these `else if` branches **before** the final `else if(a[i].StartsWith("--"))` warning branch:

```csharp
      else if(a[i]=="--serve-http"){}
      else if(a[i]=="--service"){}
      else if(a[i]=="--install-service"){}
      else if(a[i]=="--uninstall-service"){}
      else if(a[i]=="--bind"&&i+1<a.Length){i++;}
      else if(a[i]=="--port"&&i+1<a.Length){i++;}
      else if(a[i]=="--token"&&i+1<a.Length){i++;}
      else if(a[i]=="--allow-insecure"){}
```

Then, immediately **before** the existing `bool serve=false;` line (line 224), add the HTTP/service dispatch:

```csharp
    bool serveHttp=false, svc=false, installSvc=false, uninstallSvc=false;
    foreach(var x in a){ if(x=="--serve-http")serveHttp=true; else if(x=="--service")svc=true; else if(x=="--install-service")installSvc=true; else if(x=="--uninstall-service")uninstallSvc=true; }
    if(serveHttp||svc||installSvc||uninstallSvc){
      ServeOpts o=new ServeOpts(); o.Rev=rev; o.Scripts=scriptMode;
      for(int i=0;i<a.Length;i++){
        if(a[i]=="--bind"&&i+1<a.Length) o.Bind=a[++i];
        else if(a[i]=="--port"&&i+1<a.Length) int.TryParse(a[++i], out o.Port);
        else if(a[i]=="--token"&&i+1<a.Length) o.Token=a[++i];
        else if(a[i]=="--allow-insecure") o.AllowInsecure=true;
      }
      if(installSvc){ Environment.Exit(InstallService(o)); }
      if(uninstallSvc){ Environment.Exit(UninstallService(o)); }
      if(svc){ RunService(o); return; }
      Environment.Exit(ServeHttp(o));
    }
```

> Note: `InstallService`, `UninstallService`, and `RunService` are added in Task 5. To keep Task 1 compiling, temporarily stub them at the bottom of `http_serve.cs`:
> ```csharp
>   internal static int InstallService(ServeOpts o){ Console.Error.WriteLine("not implemented"); return 1; }
>   internal static int UninstallService(ServeOpts o){ Console.Error.WriteLine("not implemented"); return 1; }
>   internal static void RunService(ServeOpts o){ ServeHttp(o); }
> ```
> Task 5 replaces these stubs with the real implementations in `service.cs` (delete the stubs from `http_serve.cs` then).

- [ ] **Step 6: Add `http_serve.cs` to the build**

In `build.cmd` line 9, change:
```bat
"%CSC%" /nologo /r:System.Security.dll /out:myatg.exe myatg.cs rdp_validate.cs
```
to:
```bat
"%CSC%" /nologo /r:System.Security.dll /out:myatg.exe myatg.cs rdp_validate.cs http_serve.cs
```

In `.github/workflows/ci.yml` line 18, make the same change to the compile command.

- [ ] **Step 7: Run the smoke to verify it passes**

Run (Windows/CI): build, then the Step 1 smoke.
Expected: PASS — `healthz ok` printed, exit 0.

- [ ] **Step 8: Commit**

```bash
git add myatg.cs http_serve.cs build.cmd .github/workflows/ci.yml
git commit -m "feat: --serve-http console HTTP server with /healthz (http.sys)"
```

---

## Task 2: `POST /validate` (upload bytes → verdict) + concurrency

**Files:**
- Modify: `http_serve.cs` (`HandleRequest` body)
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `Validator.ValidateFile(string path, string rev, string scriptMode)` and `Validator.ErrJson(string,string,string)` (private statics in `myatg.cs`, reachable via `partial`); `maxBytes` (private static field).
- Produces: `POST /validate` reads the raw request body to a temp file (capped at `maxBytes`), calls `ValidateFile`, returns `200` + verdict JSON; `?rev=` / `?scripts=` query overrides.

- [ ] **Step 1: Add the failing CI smoke step**

In `.github/workflows/ci.yml`, after the `/healthz` smoke step, add:

```yaml
      - name: Smoke — POST /validate matches one-shot verdict
        shell: pwsh
        run: |
          .\myatg.exe C:\Windows\System32\whoami.exe > oneshot.json
          $p = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--port','8138' -PassThru
          Start-Sleep -Seconds 2
          try {
            $bytes = [System.IO.File]::ReadAllBytes('C:\Windows\System32\whoami.exe')
            $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8138/validate' -Method Post -Body $bytes -ContentType 'application/octet-stream' -TimeoutSec 30
            $r.Content | Out-File http.json -Encoding ascii
            $http = ($r.Content | ConvertFrom-Json)
            $one  = (Get-Content oneshot.json -Raw | ConvertFrom-Json)
            if ($http.file_sha256 -ne $one.file_sha256) { Write-Error 'sha mismatch'; exit 1 }
            if ($http.status -ne $one.status) { Write-Error 'status mismatch'; exit 1 }
            Write-Host ('validate ok: ' + $http.status)
          } finally {
            Stop-Process -Id $p.Id -Force
          }

      - name: Smoke — 8 concurrent /validate requests
        shell: pwsh
        run: |
          $p = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--port','8139' -PassThru
          Start-Sleep -Seconds 2
          try {
            $bytes = [System.IO.File]::ReadAllBytes('C:\Windows\System32\whoami.exe')
            $jobs = 1..8 | ForEach-Object {
              Start-Job -ScriptBlock {
                param($b)
                (Invoke-WebRequest -Uri 'http://127.0.0.1:8139/validate' -Method Post -Body $b -TimeoutSec 30).StatusCode
              } -ArgumentList (,$bytes)
            }
            $codes = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            if (($codes | Where-Object { $_ -ne 200 }).Count -gt 0) { Write-Error ('non-200: ' + ($codes -join ',')); exit 1 }
            Write-Host 'concurrency ok'
          } finally {
            Stop-Process -Id $p.Id -Force
          }
```

- [ ] **Step 2: Run the smoke to verify it fails**

Run (Windows/CI): build (Task 1 binary), then the steps above.
Expected: FAIL — `/validate` returns `404` (only `/healthz` exists), so the verdict parse / status check fails.

- [ ] **Step 3: Implement `/validate` in `HandleRequest`**

Replace the body of `HandleRequest` in `http_serve.cs` with:

```csharp
  static void HandleRequest(HttpListenerContext ctx, ServeOpts o){
    HttpListenerRequest req = ctx.Request;
    HttpListenerResponse res = ctx.Response;
    try {
      string path = req.Url.AbsolutePath;
      if(req.HttpMethod=="GET" && path=="/healthz"){ WriteJson(res, 200, "{\"ok\":true}"); return; }
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
```

- [ ] **Step 4: Run the smoke to verify it passes**

Run (Windows/CI): rebuild, then the Step 1 steps.
Expected: PASS — `validate ok: <status>` and `concurrency ok`; HTTP verdict's `file_sha256`/`status` equal the one-shot output.

- [ ] **Step 5: Commit**

```bash
git add http_serve.cs .github/workflows/ci.yml
git commit -m "feat: POST /validate (upload bytes -> verdict), concurrency-safe"
```

---

## Task 3: Request errors — size, method, route, empty body

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the `HandleRequest` routing from Task 2 (already returns `413`/`405`/`404`/`400`).
- Produces: CI coverage asserting those status codes. (No new product code — Task 2 already implements the branches; this task locks them with tests. If a test fails, fix the corresponding branch in `http_serve.cs`.)

- [ ] **Step 1: Add the failing CI smoke step**

In `.github/workflows/ci.yml`, after the concurrency step, add:

```yaml
      - name: Smoke — /validate error codes
        shell: pwsh
        run: |
          $p = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--port','8140','--max-size','1' -PassThru
          Start-Sleep -Seconds 2
          function Code($sb){ try { & $sb; return 0 } catch { return [int]$_.Exception.Response.StatusCode } }
          try {
            $wrongMethod = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8140/validate' -Method Get -TimeoutSec 10 }
            if ($wrongMethod -ne 405) { Write-Error "method: $wrongMethod"; exit 1 }
            $notFound = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8140/nope' -Method Post -Body 'x' -TimeoutSec 10 }
            if ($notFound -ne 404) { Write-Error "route: $notFound"; exit 1 }
            $empty = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8140/validate' -Method Post -Body ([byte[]]@()) -TimeoutSec 10 }
            if ($empty -ne 400) { Write-Error "empty: $empty"; exit 1 }
            $big = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8140/validate' -Method Post -Body (New-Object byte[] (2*1024*1024)) -TimeoutSec 30 }
            if ($big -ne 413) { Write-Error "oversize: $big"; exit 1 }
            Write-Host 'error codes ok'
          } finally {
            Stop-Process -Id $p.Id -Force
          }
```

- [ ] **Step 2: Run the smoke to verify current behavior**

Run (Windows/CI): build, then the step.
Expected: PASS for `405`/`404`/`400`/`413` if Task 2 is correct. If any code is wrong, that is the failing test — fix the matching branch in `HandleRequest` and re-run until PASS.

> Note on `--max-size`: the server starts with `--max-size 1` (1 MB) so a 2 MB body exceeds it. `--max-size` is parsed by the existing arg loop (`myatg.cs:217`) into `maxBytes` at startup — confirm that branch runs for the serve path (it does; it precedes the dispatch block).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "test: CI coverage for /validate error codes (405/404/400/413)"
```

---

## Task 4: Token auth + non-loopback fail-closed

**Files:**
- Modify: `http_serve.cs` (`HandleRequest` auth check, `FixedEquals` helper)
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `ServeOpts.Token`, `ServeOpts.AllowInsecure`, `Validator.IsLoopback` (Task 1).
- Produces: `static bool Validator.FixedEquals(string,string)`; `Authorization: Bearer <token>` enforcement on `/validate` when `Token!=null`; `ServeHttp` already refuses non-loopback-without-token (Task 1) — covered here by test.

- [ ] **Step 1: Add the failing CI smoke step**

In `.github/workflows/ci.yml`, after the error-codes step, add:

```yaml
      - name: Smoke — token auth + fail-closed bind
        shell: pwsh
        run: |
          $p = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--port','8141','--token','s3cret' -PassThru
          Start-Sleep -Seconds 2
          function Code($sb){ try { & $sb; return 0 } catch { return [int]$_.Exception.Response.StatusCode } }
          try {
            $bytes = [System.IO.File]::ReadAllBytes('C:\Windows\System32\whoami.exe')
            $noTok = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8141/validate' -Method Post -Body $bytes -TimeoutSec 30 }
            if ($noTok -ne 401) { Write-Error "missing token: $noTok"; exit 1 }
            $badTok = Code { Invoke-WebRequest -Uri 'http://127.0.0.1:8141/validate' -Method Post -Body $bytes -Headers @{Authorization='Bearer nope'} -TimeoutSec 30 }
            if ($badTok -ne 401) { Write-Error "bad token: $badTok"; exit 1 }
            $ok = (Invoke-WebRequest -Uri 'http://127.0.0.1:8141/validate' -Method Post -Body $bytes -Headers @{Authorization='Bearer s3cret'} -TimeoutSec 30).StatusCode
            if ($ok -ne 200) { Write-Error "good token: $ok"; exit 1 }
            Write-Host 'token auth ok'
          } finally {
            Stop-Process -Id $p.Id -Force
          }
          # fail-closed: non-loopback bind without token must exit non-zero and not listen
          $q = Start-Process -FilePath .\myatg.exe -ArgumentList '--serve-http','--bind','0.0.0.0','--port','8142' -Wait -PassThru
          if ($q.ExitCode -eq 0) { Write-Error 'expected non-zero exit for insecure bind'; exit 1 }
          Write-Host 'fail-closed ok'
```

- [ ] **Step 2: Run the smoke to verify it fails**

Run (Windows/CI): build (Task 2 binary), then the step.
Expected: FAIL — no token enforcement yet, so the no-token request returns `200` instead of `401`.

- [ ] **Step 3: Add `FixedEquals` and the auth check**

In `http_serve.cs`, add the helper (place it next to `WriteJson`):

```csharp
  // Constant-time compare so the token check leaks no timing signal.
  static bool FixedEquals(string a, string b){
    if(a==null||b==null) return false;
    byte[] x=Encoding.UTF8.GetBytes(a), y=Encoding.UTF8.GetBytes(b);
    int diff = x.Length ^ y.Length;
    for(int i=0;i<x.Length;i++) diff |= x[i] ^ y[(i<y.Length)?i:0];
    return diff==0;
  }
```

In `HandleRequest`, immediately **after** the `/healthz` line and **before** the `if(path!="/validate")` line, insert the auth gate:

```csharp
      if(o.Token!=null){
        string hdr=req.Headers["Authorization"];
        string bearer=(hdr!=null && hdr.StartsWith("Bearer ")) ? hdr.Substring(7) : null;
        if(!FixedEquals(o.Token, bearer)){ WriteJson(res, 401, "{\"error\":\"unauthorized\"}"); return; }
      }
```

(The fail-closed non-loopback check already exists at the top of `ServeHttp` from Task 1; the test exercises it.)

- [ ] **Step 4: Run the smoke to verify it passes**

Run (Windows/CI): rebuild, then the step.
Expected: PASS — `token auth ok` and `fail-closed ok`.

- [ ] **Step 5: Commit**

```bash
git add http_serve.cs .github/workflows/ci.yml
git commit -m "feat: bearer-token auth (constant-time) + fail-closed non-loopback bind"
```

---

## Task 5: Windows service — entry, install/uninstall, CI smoke

**Files:**
- Create: `service.cs`
- Modify: `http_serve.cs` (remove the Task 1 stubs for `InstallService`/`UninstallService`/`RunService`)
- Modify: `build.cmd:9`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `Validator.ServeOpts`, `Validator.ServeHttp`, `Validator.StopHttp` (Task 1).
- Produces: `class MyatgService : ServiceBase`; `internal static void Validator.RunService(ServeOpts)`; `internal static int Validator.InstallService(ServeOpts)`; `internal static int Validator.UninstallService()`. Service name `myatg`, account `NT SERVICE\myatg`, scoped urlacl, restart-on-failure.

- [ ] **Step 1: Add the failing CI smoke step**

In `.github/workflows/ci.yml`, after the token step, add (GitHub `windows-latest` runs elevated, so `sc`/`netsh` succeed):

```yaml
      - name: Smoke — install service, healthz, uninstall
        shell: pwsh
        run: |
          $exe = (Resolve-Path .\myatg.exe).Path
          & $exe --install-service --port 8143
          if ($LASTEXITCODE -ne 0) { Write-Error "install rc=$LASTEXITCODE"; exit 1 }
          Start-Sleep -Seconds 3
          $svc = Get-Service myatg
          if ($svc.Status -ne 'Running') { Write-Error "service status: $($svc.Status)"; exit 1 }
          $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8143/healthz' -TimeoutSec 10
          if (-not $r.ok) { Write-Error 'service healthz not ok'; exit 1 }
          Write-Host 'service running + healthz ok'
          & $exe --uninstall-service --port 8143
          if ($LASTEXITCODE -ne 0) { Write-Error "uninstall rc=$LASTEXITCODE"; exit 1 }
          Start-Sleep -Seconds 2
          if (Get-Service myatg -ErrorAction SilentlyContinue) { Write-Error 'service still present'; exit 1 }
          Write-Host 'uninstall ok'
```

- [ ] **Step 2: Run the smoke to verify it fails**

Run (Windows/CI): build (Task 4 binary), then the step.
Expected: FAIL — `--install-service` hits the Task 1 stub (`not implemented`, rc 1).

- [ ] **Step 3: Remove the Task 1 stubs**

In `http_serve.cs`, delete the three stub methods added in Task 1 Step 5 (`InstallService`, `UninstallService`, `RunService`).

- [ ] **Step 4: Create `service.cs`**

```csharp
using System;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;

// SCM-hosted service wrapper. Launched by Windows via the --service flag.
public class MyatgService : ServiceBase {
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
```

- [ ] **Step 5: Add the service args + `System.ServiceProcess.dll` to the build**

In `build.cmd` line 9 and `.github/workflows/ci.yml` line 18, change the compile command to:
```bat
"%CSC%" /nologo /r:System.Security.dll /r:System.ServiceProcess.dll /out:myatg.exe myatg.cs rdp_validate.cs http_serve.cs service.cs
```

- [ ] **Step 6: Run the smoke to verify it passes**

Run (Windows/CI): rebuild, then the Step 1 step.
Expected: PASS — `service running + healthz ok`, then `uninstall ok`. (`Get-Service myatg` gone afterward.)

- [ ] **Step 7: Commit**

```bash
git add service.cs http_serve.cs myatg.cs build.cmd .github/workflows/ci.yml
git commit -m "feat: Windows service mode (NT SERVICE\\myatg, scoped urlacl, auto-restart)"
```

---

## Task 6: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: all flags/endpoints from Tasks 1–5.
- Produces: a README section documenting HTTP serve + service install.

- [ ] **Step 1: Add an HTTP serve section to `README.md`**

Add a new section (place it after the existing `--serve` documentation). Use real, copy-pasteable commands:

```markdown
### HTTP serve mode

Run myatg as a persistent local HTTP validator. Upload file **bytes**; get the same JSON verdict.

**Console (foreground):**

    myatg --serve-http --port 8137

**Endpoints:**

- `GET  /healthz`  → `{"ok":true}` (no auth)
- `POST /validate` → body = raw file bytes; returns the verdict JSON.
  Optional query overrides: `?rev=online|offline|none`, `?scripts=<mode>`.

**Example:**

    curl --data-binary @sample.exe http://127.0.0.1:8137/validate

**Flags:** `--bind <addr>` (default `127.0.0.1`), `--port <n>` (default `8137`),
`--token <secret>` (require `Authorization: Bearer <secret>`), `--allow-insecure`
(permit a non-loopback bind without a token — not recommended).
Binding a non-loopback address without `--token` refuses to start.

`--gv`, `--max-size`, `--rev`, `--scripts` are read once at startup and apply to the
whole server (`--rev`/`--scripts` can be overridden per request via query string).

**As a least-privilege Windows service** (run once, elevated):

    myatg --install-service --port 8137

Creates service `myatg` under the virtual account `NT SERVICE\myatg`, reserves the
loopback URL (`netsh http add urlacl`) scoped to that account, sets auto-start and
restart-on-failure. The service then runs unelevated. Remove it with:

    myatg --uninstall-service --port 8137
```

- [ ] **Step 2: Verify the docs match the flags**

Read back the section and confirm every flag/endpoint name matches the code in `http_serve.cs` and `service.cs` (`--serve-http`, `--bind`, `--port`, `--token`, `--allow-insecure`, `--install-service`, `--uninstall-service`, `/healthz`, `/validate`, `?rev=`, `?scripts=`).
Expected: all names consistent.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: HTTP serve mode + least-priv Windows service install"
```

---

## Final: update the PR

After Task 6, update PR #2's title/description to reflect the expanded scope (stdin **and** HTTP serve):

```bash
gh pr edit 2 --title "feat: persistent-validator serve modes (stdin + HTTP service)"
```

Then push the branch and let CI run all smoke steps:

```bash
git push origin feat/serve-mode
```
