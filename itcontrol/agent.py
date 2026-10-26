"""IT Operation endpoint agent. Inventory + allowlisted admin actions for authorized devices."""
import os,sys,json,uuid,platform,socket,subprocess,time,hashlib,getpass,re,shutil
from pathlib import Path
import psutil,requests
ROOT = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
CFG = ROOT / 'agent_config.json'
IDFILE = ROOT / '.agent_id'
_prev_net=None; _prev_net_ts=None
_fg_key=None; _fg_since=None
_icon_cache={}
def config(): return json.loads(CFG.read_text(encoding='utf-8'))
def cmd(args,timeout=12):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False,encoding='utf-8',errors='replace'); return p.returncode,(p.stdout or '').strip(),(p.stderr or '').strip()
 except Exception as e:return 1,'',str(e)
def ps(script,timeout=20):
 return cmd(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-Command',script],timeout)
def agent_id():
 if IDFILE.exists():return IDFILE.read_text().strip()
 x=str(uuid.uuid4());IDFILE.write_text(x);return x
def machine():
 if platform.system()=='Windows':
  _,out,_=ps("$c=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS;@{maker=$c.Manufacturer;model=$c.Model;serial=$b.SerialNumber}|ConvertTo-Json -Compress")
  try:j=json.loads(out);return j.get('maker'),j.get('model'),j.get('serial')
  except:pass
 return platform.node(),platform.machine(),None
def software():
 s=[]
 if platform.system()=='Windows':
  # Read uninstall registry directly; avoids PowerShell JSON shape/encoding failures.
  try:
   import winreg
   roots=[(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',winreg.KEY_WOW64_64KEY),
          (winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',winreg.KEY_WOW64_32KEY),
          (winreg.HKEY_CURRENT_USER,r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',0)]
   seen=set()
   for root,path,view in roots:
    try: base=winreg.OpenKey(root,path,0,winreg.KEY_READ|view)
    except OSError: continue
    with base:
     for i in range(winreg.QueryInfoKey(base)[0]):
      try: sub=winreg.EnumKey(base,i); key=winreg.OpenKey(base,sub,0,winreg.KEY_READ|view)
      except OSError: continue
      with key:
       def val(name):
        try:return winreg.QueryValueEx(key,name)[0]
        except OSError:return None
       name=val('DisplayName')
       if not name: continue
       version=val('DisplayVersion'); publisher=val('Publisher'); ident=(str(name).strip().lower(),str(version or '').strip().lower(),str(publisher or '').strip().lower())
       if ident in seen: continue
       seen.add(ident)
       rawdate=str(val('InstallDate') or '').strip()
       install_date=rawdate
       if len(rawdate)==8 and rawdate.isdigit(): install_date=f'{rawdate[0:4]}-{rawdate[4:6]}-{rawdate[6:8]}'
       loc=val('InstallLocation')
       s.append({'name':str(name).strip(),'version':str(version).strip() if version else None,'publisher':str(publisher).strip() if publisher else None,'install_date':install_date or None,'install_location':str(loc).strip() if loc else None,'uninstall_string':val('UninstallString'),'estimated_size_kb':val('EstimatedSize'),'registry_source':str(path+'\\'+sub),'signature_status':'Not checked','license_status':'Unknown'})
  except Exception as ex:
   print('software inventory registry error:',repr(ex))
 elif platform.system()=='Darwin':
  _,out,_=cmd(['system_profiler','SPApplicationsDataType','-json'],30)
  try:
   for x in json.loads(out).get('SPApplicationsDataType',[]):s.append({'name':x.get('_name'),'version':x.get('version'),'publisher':x.get('obtained_from'),'install_location':x.get('path'),'install_date':None,'signature_status':'Not checked','license_status':'Unknown'})
  except Exception as ex: print('software inventory error:',repr(ex))
 else:
  rc,out,_=cmd(['dpkg-query','-W','-f=${binary:Package}\t${Version}\t${Maintainer}\n'],30)
  if rc==0:
   for line in out.splitlines():
    parts=line.split('\t');s.append({'name':parts[0],'version':parts[1] if len(parts)>1 else None,'publisher':parts[2] if len(parts)>2 else None,'install_date':None,'install_location':None,'signature_status':'Not checked','license_status':'Unknown'})
 return sorted(s,key=lambda x:(x.get('name') or '').lower())[:3000]

def disks():
 out=[]
 for p in psutil.disk_partitions(all=False):
  try:u=psutil.disk_usage(p.mountpoint);out.append({'mount':p.mountpoint,'filesystem':p.fstype,'total_gb':round(u.total/2**30,2),'used_gb':round(u.used/2**30,2),'free_gb':round(u.free/2**30,2),'percent_used':u.percent})
  except:pass
 return out
def network():
 out=[];stats=psutil.net_if_stats()
 for name,addrs in psutil.net_if_addrs().items():
  ip=mac=None
  for a in addrs:
   if a.family==socket.AF_INET and not a.address.startswith('127.'):ip=a.address
   if getattr(psutil,'AF_LINK',object())==a.family or str(a.family).endswith('AF_PACKET'):mac=a.address
  if ip or mac:out.append({'interface':name,'ip':ip,'mac':mac,'is_up':stats[name].isup if name in stats else None})
 return out
def network_throughput():
 global _prev_net, _prev_net_ts
 now_ts=time.time(); counters=psutil.net_io_counters(pernic=True); current={k:(v.bytes_recv,v.bytes_sent) for k,v in counters.items()}
 result=[]
 if _prev_net is not None and _prev_net_ts is not None:
  dt=max(0.001,now_ts-_prev_net_ts)
  for name,(recv,sent) in current.items():
   if name in _prev_net:
    prev_recv,prev_sent=_prev_net[name]
    result.append({'interface':name,'download_mbps':round(max(0,recv-prev_recv)*8/dt/1_000_000,3),'upload_mbps':round(max(0,sent-prev_sent)*8/dt/1_000_000,3),'sample_seconds':round(dt,1)})
 _prev_net=current; _prev_net_ts=now_ts
 return result
def security():
 d={'antivirus':'Unknown','antivirus_signature_last_updated':None,'antivirus_last_quick_scan':None,'firewall':'Unknown','encryption':'Unknown','note':'Indikator teknis; bukan bukti aplikasi asli/crack atau status lisensi.'}
 if platform.system()=='Windows':
  _,o,_=ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName | ConvertTo-Json -Compress")
  try:d['antivirus']=json.loads(o) if o else 'Not detected'
  except:d['antivirus']=o or 'Unknown'
  _,o,_=ps("Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusSignatureLastUpdated,AntivirusSignatureVersion,RealTimeProtectionEnabled,AntivirusEnabled,QuickScanEndTime,FullScanEndTime | ConvertTo-Json -Compress")
  try:
   m=json.loads(o) if o else {}
   if isinstance(m,dict):
    d['defender']=m
    d['antivirus_signature_last_updated']=m.get('AntivirusSignatureLastUpdated')
    d['antivirus_last_quick_scan']=m.get('QuickScanEndTime')
  except:pass
  _,o,_=ps("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
  try:d['firewall']=json.loads(o) if o else 'Unknown'
  except:d['firewall']=o or 'Unknown'
  # Distinguish firewall profile enabled state from the network category currently in use.
  _,no,_=ps("Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity | ConvertTo-Json -Compress")
  try:
   profiles=json.loads(no) if no else []
   if isinstance(profiles,dict): profiles=[profiles]
   if profiles:
    active=profiles[0]; iface=str(active.get('InterfaceAlias') or '')
    ni=next((x for x in network() if str(x.get('interface') or '').casefold()==iface.casefold()),{})
    d['active_network']={'interface':iface,'category':active.get('NetworkCategory'),'connectivity':active.get('IPv4Connectivity'),'profile':active.get('NetworkCategory'),'ip':ni.get('ip'),'gateway':None}
  except Exception: d['active_network']={'profile':'Unavailable','category':'Unavailable','interface':'Unavailable','ip':'Unavailable','gateway':'Unavailable'}
  _,o,_=ps("Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Compress")
  try:d['encryption']=json.loads(o) if o else 'Unavailable / permission required'
  except:d['encryption']=o or 'Unavailable'
 return d
def foreground_app():
 """Return the current Windows foreground process and uninterrupted active-window duration."""
 global _fg_key, _fg_since
 if platform.system()!='Windows': return {'process':None,'window_title':None,'active_seconds_display':'Unavailable','sampled_at':time.strftime('%Y-%m-%d %H:%M:%S')}
 try:
  import ctypes
  from ctypes import wintypes
  user32=ctypes.windll.user32; hwnd=user32.GetForegroundWindow()
  if not hwnd: raise RuntimeError('No foreground window')
  length=user32.GetWindowTextLengthW(hwnd); buf=ctypes.create_unicode_buffer(min(max(length+1,1),2048)); user32.GetWindowTextW(hwnd,buf,len(buf))
  pid=wintypes.DWORD(); user32.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
  try: proc=psutil.Process(pid.value).name()
  except Exception: proc=None
  title=buf.value[:500]
  key=f'{pid.value}|{proc}|{title}'
  now_mono=time.monotonic()
  if key!=_fg_key or _fg_since is None: _fg_key=key; _fg_since=now_mono
  seconds=max(0,int(now_mono-_fg_since))
  return {'process':proc,'window_title':title,'user_name':getpass.getuser(),'session_locked':str(proc or '').lower()=='lockapp.exe','active_seconds':seconds,'active_seconds_display':f'{seconds//3600}h {(seconds%3600)//60}m {seconds%60}s','sampled_at':time.strftime('%Y-%m-%d %H:%M:%S')}
 except Exception as ex:
  return {'process':None,'window_title':None,'active_seconds_display':'Unavailable','sampled_at':time.strftime('%Y-%m-%d %H:%M:%S'),'reason':str(ex)[:160]}

def _attach_native_icons(rows):
 """Extract real associated executable icons on Windows; no invented initials/logos."""
 if platform.system() != 'Windows': return
 paths=[]
 for row in rows:
  path=row.get('executable')
  if path and os.path.isfile(path) and path not in _icon_cache and path not in paths: paths.append(path)
  if len(paths)>=45: break
 if paths:
  try:
   import base64
   payload=base64.b64encode(json.dumps(paths).encode('utf-8')).decode('ascii')
   script="$ErrorActionPreference='SilentlyContinue';Add-Type -AssemblyName System.Drawing;$raw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+payload+"'));$paths=ConvertFrom-Json $raw;$out=@{};foreach($p in $paths){try{$ic=[System.Drawing.Icon]::ExtractAssociatedIcon([string]$p);if($ic){$bm=$ic.ToBitmap();$ms=New-Object IO.MemoryStream;$bm.Save($ms,[System.Drawing.Imaging.ImageFormat]::Png);$out[[string]$p]=[Convert]::ToBase64String($ms.ToArray());$ms.Dispose();$bm.Dispose();$ic.Dispose()}}catch{}};$out|ConvertTo-Json -Compress -Depth 3"
   rc,out,_=ps(script,timeout=25)
   if rc==0 and out:
    data=json.loads(out)
    if isinstance(data,dict):
     for path,b64 in data.items():
      if isinstance(b64,str) and len(b64)<180000: _icon_cache[path]='data:image/png;base64,'+b64
   for path in paths: _icon_cache.setdefault(path,None)
  except Exception: pass
 for row in rows:
  path=row.get('executable')
  if path and path in _icon_cache: row['icon_data_uri']=_icon_cache[path]

def running_processes():
 """Return visible process metadata and native executable icons where Windows exposes them."""
 rows=[]
 try:
  for p in psutil.process_iter(['pid','name','username','exe','status','create_time','memory_info']):
   try:
    i=p.info; mem=i.get('memory_info')
    rows.append({'pid':i.get('pid'),'name':i.get('name') or 'Unknown','user':i.get('username') or 'Unknown',
     'executable':i.get('exe'),'status':i.get('status'),'started_at':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(i['create_time'])) if i.get('create_time') else None,
     'memory_mb':round(mem.rss/2**20,1) if mem else None})
   except (psutil.NoSuchProcess,psutil.AccessDenied,psutil.ZombieProcess): pass
  _attach_native_icons(rows)
 except Exception as ex:
  return {'items':[],'error':str(ex)[:200],'sampled_at':time.strftime('%Y-%m-%d %H:%M:%S')}
 return {'items':sorted(rows,key=lambda x:(x.get('name') or '').lower()),'sampled_at':time.strftime('%Y-%m-%d %H:%M:%S')}
def collect():
 maker,model,serial=machine(); vm=psutil.virtual_memory(); cpu=psutil.cpu_percent(interval=0.25)
 osdet={'name':platform.system(),'release':platform.release(),'version':platform.version(),'architecture':platform.machine()}
 cpu_name=platform.processor() or 'Unknown'
 if platform.system()=='Windows':
  _,o,_=ps(r"$os=Get-CimInstance Win32_OperatingSystem;$cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';[PSCustomObject]@{Caption=$os.Caption;Version=$os.Version;BuildNumber=$os.BuildNumber;Architecture=$os.OSArchitecture;InstallDate=$os.InstallDate;DisplayVersion=$cv.DisplayVersion;EditionID=$cv.EditionID;ProductName=$cv.ProductName}|ConvertTo-Json -Compress")
  try:
   j=json.loads(o); osdet.update(j)
  except:pass
  _,o,_=ps("Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name")
  if o:cpu_name=o.splitlines()[0].strip()
 return {'agent_id':agent_id(),'hostname':socket.gethostname(),'os_name':osdet.get('Caption') or osdet.get('ProductName') or osdet['name'],'os_release':osdet.get('DisplayVersion') or osdet.get('release'),'os_version':osdet.get('BuildNumber') or osdet.get('version'),'os_detail':osdet,'architecture':osdet.get('Architecture') or osdet['architecture'],'manufacturer':maker,'model':model,'serial_number':serial,'cpu':cpu_name,'cpu_cores':psutil.cpu_count(logical=True),'cpu_percent':cpu,'ram_total_gb':round(vm.total/2**30,2),'ram_used_gb':round(vm.used/2**30,2),'ram_percent':vm.percent,'disks':disks(),'network':network(),'network_throughput':network_throughput(),'software':software(),'security':security(),'foreground_app':foreground_app(),'running_processes':running_processes()}
def applocker_rule(action, app_name):
 # Apply or remove a narrowly scoped executable-name deny rule in the local AppLocker policy.
 if platform.system()!='Windows': raise RuntimeError('AppLocker application control is Windows-only.')
 import re
 name=str(app_name or '').strip()
 if not re.fullmatch(r'[A-Za-z0-9._ -]{1,120}',name) or name in ('.','..'): raise RuntimeError('Executable name is invalid.')
 if not name.lower().endswith('.exe'): name += '.exe'
 safe=name.replace("'","''")
 script=r'''$ErrorActionPreference='Stop'
$service=Get-Service AppIDSvc -ErrorAction SilentlyContinue
if(-not $service){throw 'AppLocker/Application Identity service is unavailable. Check Windows edition and policy support.'}
try{ if($service.Status -ne 'Running'){ Set-Service AppIDSvc -StartupType Automatic; Start-Service AppIDSvc -ErrorAction Stop } }catch{ throw ('Cannot start Application Identity service: '+$_.Exception.Message) }
[xml]$xml=Get-AppLockerPolicy -Local -Xml
if(-not $xml.AppLockerPolicy){throw 'Unable to read the local AppLocker policy.'}
$exe=$xml.AppLockerPolicy.RuleCollection | Where-Object {$_.Type -eq 'Exe'} | Select-Object -First 1
if(-not $exe){$exe=$xml.CreateElement('RuleCollection');$exe.SetAttribute('Type','Exe');$exe.SetAttribute('EnforcementMode','Enabled');[void]$xml.AppLockerPolicy.AppendChild($exe)}
$ruleName='ITOPS_BLOCK_'+$env:COMPUTERNAME+'_'+'__APP__'
$existing=@($exe.FilePathRule | Where-Object {$_.Name -eq $ruleName})
if('__ACTION__' -eq 'block'){
 if(-not $existing){$r=$xml.CreateElement('FilePathRule');$r.SetAttribute('Id',[guid]::NewGuid().ToString());$r.SetAttribute('Name',$ruleName);$r.SetAttribute('Description','Created by IT Operation Control Tower; blocks selected executable by file name.');$r.SetAttribute('UserOrGroupSid','S-1-1-0');$r.SetAttribute('Action','Deny');$cond=$xml.CreateElement('Conditions');$path=$xml.CreateElement('FilePathCondition');$path.SetAttribute('Path',('*'+[char]92+'__APP__'));[void]$cond.AppendChild($path);[void]$r.AppendChild($cond);[void]$exe.AppendChild($r)}
}else{foreach($r in $existing){[void]$exe.RemoveChild($r)}}
$tmp=[IO.Path]::Combine([IO.Path]::GetTempPath(),([guid]::NewGuid().ToString()+'.xml'));$xml.Save($tmp)
try{Set-AppLockerPolicy -XmlPolicy $tmp -ErrorAction Stop; Get-AppLockerPolicy -Local | Out-Null}finally{Remove-Item $tmp -Force -ErrorAction SilentlyContinue}
[pscustomobject]@{action='__ACTION__';executable='__APP__';rule=$ruleName;status='Policy submitted; validate by attempting to launch the application and reviewing AppLocker event logs.'}|ConvertTo-Json -Compress'''
 script=script.replace('__APP__',safe).replace('__ACTION__',action)
 rc,out,err=ps(script,35)
 if rc: raise RuntimeError((err or out or 'AppLocker policy command failed.')[-2500:])
 return {'message':out or 'AppLocker policy command completed. Verify enforcement on this Windows edition.','action':action,'executable':name,'note':'Policy changes can affect application launches. Test with a non-critical application and verify event logs.'}

def run_action(a,params):
 if a in ('refresh_inventory','hardware_health','software_inventory','security_scan'):return {'inventory':collect()}
 if a=='disk_report':return disks()
 if a=='network_report':return network()
 if a=='connectivity_test':
  results=[]
  for host in ('1.1.1.1','8.8.8.8'):
   args=['ping','-n','2','-w','1000',host] if platform.system()=='Windows' else ['ping','-c','2','-W','1',host]
   rc,out,err=cmd(args,6);results.append({'target':host,'ok':rc==0,'output':out[-1000:] or err})
  return results
 if a=='process_summary':
  items=[]
  for p in psutil.process_iter(['pid','name','username','cpu_percent','memory_info']):
   try:
    i=p.info;mem=i.get('memory_info');items.append({'pid':i['pid'],'name':i['name'],'user':i['username'],'cpu_percent':i.get('cpu_percent'),'memory_mb':round(mem.rss/2**20,1) if mem else None})
   except:pass
  return {'cpu_percent':psutil.cpu_percent(interval=.25),'ram_percent':psutil.virtual_memory().percent,'processes':sorted(items,key=lambda x:x.get('memory_mb') or 0,reverse=True)[:80]}
 if a in ('restart_endpoint','shutdown_endpoint'):
  if platform.system()!='Windows':raise RuntimeError('Power action hanya didukung pada Windows saat ini.')
  args=['shutdown.exe','/r' if a=='restart_endpoint' else '/s','/t','60','/c','IT Operation authorized action'];rc,out,err=cmd(args,8)
  if rc:raise RuntimeError(err or out or 'Windows menolak perintah. Coba jalankan agent dengan hak yang sesuai.')
  return {'message':'Accepted by Windows; delay 60s. Cancel locally: shutdown.exe /a'}
 if a in ('install_app','uninstall_app'):
  if platform.system()!='Windows':raise RuntimeError('Install/uninstall is currently supported on Windows only.')
  pkg=str(params.get('package_id','')).strip()
  if not pkg or len(pkg)>260 or any(ord(c)<32 for c in pkg):raise RuntimeError('Application selection is invalid: choose an installed application from this endpoint inventory and refresh the inventory if needed.')
  if a=='install_app':
   if not re.fullmatch(r'[A-Za-z0-9._+-]{2,160}',pkg):raise RuntimeError('Choose an approved package from the catalog.')
   winget=shutil.which('winget')
   if not winget and platform.system()=='Windows':
    candidates=list(Path(os.environ.get('LOCALAPPDATA',r'C:\Users\Default\AppData\Local')) .glob('Microsoft/WindowsApps/winget.exe'))
    candidates += list(Path(r'C:\Program Files\WindowsApps').glob('Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe/winget.exe'))
    winget=next((str(x) for x in candidates if x.exists()),None)
   if not winget: raise RuntimeError('WinGet tidak ditemukan pada endpoint ini. Instal/aktifkan App Installer pada endpoint, lalu restart agent.')
   args=[winget,'install','--id',pkg,'--exact','--source','winget','--accept-package-agreements','--accept-source-agreements','--disable-interactivity','--silent']
   rc,out,err=cmd(args,1200); result_text=(out+'\n'+err).strip()[-12000:]
   if rc!=0: raise RuntimeError(f'winget install failed with exit code {rc}: {result_text or "No output returned"}. If the installer does not support silent mode or requires user interaction, install it interactively from the endpoint.')
   time.sleep(3)
   installed_after=software()
   expected_name=str(params.get('package_name') or '').strip().casefold()
   verified=next((x for x in installed_after if (x.get('name') or '').casefold()==(expected_name or pkg.casefold()) or str(x.get('package_id') or '').casefold()==pkg.casefold()),None)
   return {'exit_code':rc,'package_id':pkg,'output':result_text or 'WinGet completed.','verification':'Installed app found in registry inventory' if verified else 'WinGet returned success; app not yet found in registry inventory. Refresh inventory and verify manually.'}
  installed=software()
  match=next((x for x in installed if (x.get('name') or '').casefold()==pkg.casefold()),None)
  if not match: raise RuntimeError('Application not found in this endpoint inventory. Refresh inventory and select it again.')
  us=str(match.get('uninstall_string') or '').strip()
  if not us: raise RuntimeError('Windows does not provide an uninstall command for this application; automatic uninstall is unavailable.')
  import base64
  # Parse the registry command into executable + arguments; avoid cmd.exe quoting corruption.
  # MSI is normalized to uninstall mode and quiet switches; EXE uninstallers keep their vendor arguments.
  script = r"""$ErrorActionPreference='Stop'
$u = __UNINSTALL_COMMAND__
if ([string]::IsNullOrWhiteSpace($u)) { throw 'Registry UninstallString is empty.' }
$exe = $null; $argsText = ''
if ($u -match '^\s*"([^"]+)"\s*(.*)$') { $exe=$Matches[1]; $argsText=$Matches[2] }
elseif ($u -match '^\s*(.+?\.exe)\s*(.*)$') { $exe=$Matches[1].Trim('"'); $argsText=$Matches[2] }
else { throw ('Cannot parse uninstall executable from registry command: ' + $u) }
if (-not (Test-Path -LiteralPath $exe) -and $exe -notmatch '^(?i)msiexec(\.exe)?$') {
  $resolved = Get-Command $exe -ErrorAction SilentlyContinue
  if ($resolved) { $exe=$resolved.Source } else { throw ('Uninstaller executable not found: ' + $exe) }
}
if ($exe -match '(?i)msiexec(\.exe)?$') {
  $argsText = $argsText -replace '(?i)(^|\s)/I(?=\s*\{)', '$1/X'
  if ($argsText -notmatch '(?i)(/q|/quiet|/passive)') { $argsText += ' /qn /norestart' }
  if ($argsText -notmatch '(?i)/x') { throw ('MSI uninstall command does not contain a product code: ' + $argsText) }
} elseif ($exe -match '(?i)\\(unins\d*|uninstall|uninstaller)\.exe$' -or $exe -match '(?i)\\unins\d*\.exe$') {
  # Inno Setup uninstallers support silent mode. Do not add these flags to unknown vendors.
  if ($argsText -notmatch '(?i)/VERYSILENT|/SILENT') { $argsText += ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART' }
} elseif ($exe -match '(?i)\\(nsuninstall|uninstall)\.exe$') {
  # NSIS uses uppercase /S for unattended uninstall.
  if ($argsText -notmatch '(?i)(^|\s)/S(\s|$)') { $argsText += ' /S' }
}
if ([string]::IsNullOrWhiteSpace($argsText)) { $p = Start-Process -FilePath $exe -Wait -PassThru -ErrorAction Stop } else { $p = Start-Process -FilePath $exe -ArgumentList $argsText -Wait -PassThru -ErrorAction Stop }
if ($null -eq $p.ExitCode) { throw 'Uninstaller exited without an exit code.' }
if ($p.ExitCode -notin @(0,1605,1614,1641,3010)) { throw ('Uninstaller returned exit code ' + $p.ExitCode) }
[pscustomobject]@{exit_code=$p.ExitCode; executable=$exe; arguments=$argsText; reboot_required=($p.ExitCode -in @(1641,3010)); output='Uninstaller process completed.'} | ConvertTo-Json -Compress
""".replace('__UNINSTALL_COMMAND__', "'" + us.replace("'", "''") + "'")
  enc=base64.b64encode(script.encode('utf-16le')).decode('ascii')
  rc,out,err=cmd(['powershell','-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',enc],360)
  if rc!=0: raise RuntimeError(f'Uninstaller failed: {(err or out or "PowerShell returned no error detail")[-2500:]}')
  try: result=json.loads(out)
  except Exception: result={'output':out[-2500:]}
  # Verify removal from the registry inventory; do not label success if the app is still listed.
  time.sleep(2)
  still=next((x for x in software() if (x.get('name') or '').casefold()==pkg.casefold()),None)
  if still and not result.get('reboot_required'):
   raise RuntimeError(f"Uninstaller returned exit code {result.get('exit_code')}, but '{pkg}' is still present in the Windows uninstall inventory. It may require a vendor-specific command, elevation, or reboot. Details: {json.dumps(result,ensure_ascii=False)[:1800]}")
  shortcut_cleanup=[]
  if not still and platform.system()=='Windows':
   # Remove only exact-name shortcuts; never delete arbitrary desktop files.
   roots=[Path(os.environ.get('USERPROFILE',''))/'Desktop',Path(os.environ.get('PUBLIC',r'C:\Users\Public'))/'Desktop']
   for root in roots:
    try:
     for shortcut in root.iterdir():
      if shortcut.is_file() and shortcut.suffix.lower() in ('.lnk','.url') and shortcut.stem.casefold()==pkg.casefold():
       try: shortcut.unlink(); shortcut_cleanup.append(str(shortcut))
       except OSError: pass
    except OSError: pass
  return {'exit_code':result.get('exit_code',0),'application':pkg,'reboot_required':bool(result.get('reboot_required')),'output':result.get('output','Uninstaller completed and inventory no longer lists the application.'),'verification':'Still listed; reboot required' if still else 'Not present in registry inventory after uninstall.','desktop_shortcuts_removed':shortcut_cleanup} 
 if a=='notify_client':
  msg=params.get('message','IT Operation: pemberitahuan admin')
  if platform.system()=='Windows':
   safe=msg.replace("'","''")
   rc,out,err=ps(f"Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('{safe}','IT Operation Notification') | Out-Null",10)
   if rc==0:return {'message':'Notification dialog invoked in agent session.'}
   rc,out,err=cmd(['msg.exe','*',msg],10)
   return {'message':out or err or 'Notification attempted; visibility depends on user session/permissions.'}
  return {'message':'Notification display currently supported on Windows only.'}
 if a in ('app_block','app_unblock'):
  return applocker_rule('block' if a=='app_block' else 'unblock',params.get('app_name',''))
 if a=='stop_application':
  if platform.system()!='Windows': raise RuntimeError('Stop application saat ini hanya didukung di Windows.')
  name=str(params.get('app_name','')).strip()
  if not re.fullmatch(r'[A-Za-z0-9._ -]{1,120}',name) or name in ('.','..'): raise RuntimeError('Nama proses tidak valid.')
  if not name.lower().endswith('.exe'): name += '.exe'
  # Explicitly best-effort: terminate only the named process; does not create a persistent OS block policy.
  rc,out,err=cmd(['taskkill.exe','/IM',name,'/T','/F'],15)
  if rc: raise RuntimeError((err or out or 'Proses tidak ditemukan atau akses ditolak.')+' Ini hanya menghentikan proses berjalan, bukan blokir permanen.')
  return {'message':f'Perintah penghentian dikirim untuk {name}. Ini bukan blokir permanen; aplikasi dapat dibuka kembali.', 'output':out[-2000:]}
 if a=='remote_assist':
  if platform.system()!='Windows': raise RuntimeError('Remote Support Quick Assist hanya tersedia pada Windows.')
  # Avoid URI fallback that can open Microsoft Store when Quick Assist is not installed.
  candidates=[os.path.join(os.environ.get('WINDIR',r'C:\Windows'),'System32','QuickAssist.exe'), os.path.join(os.environ.get('LOCALAPPDATA',''), 'Microsoft','WindowsApps','QuickAssist.exe')]
  exe=next((x for x in candidates if x and os.path.isfile(x)),None)
  if exe:
   try: subprocess.Popen([exe], close_fds=True)
   except Exception as e: raise RuntimeError('Quick Assist ditemukan tetapi gagal dijalankan: '+str(e))
   return {'message':'Quick Assist dicoba dibuka. User tetap harus menyetujui sesi. Ini bukan remote desktop unattended.'}
  # Do not invoke quickassist: URI because some Windows builds redirect it to Microsoft Store.
  raise RuntimeError('Quick Assist tidak ditemukan sebagai aplikasi terpasang. Tidak membuka Microsoft Store otomatis. Pasang Quick Assist dari sumber resmi atau integrasikan solusi remote-support terkelola. Remote desktop penuh belum tersedia di prototype ini.')
 raise RuntimeError('Action not allowlisted')
def main():
 c=config(); interval=max(15,int(c.get('interval_seconds',30))); print('IT Operation Control Tower agent active; Ctrl+C to stop. Only use on authorized endpoint.')
 while True:
  try:
   payload=collect(); r=requests.post(c['server_url'],json=payload,headers={'X-API-Key':c['api_key']},timeout=25); print(time.strftime('%H:%M:%S'),'heartbeat',r.status_code,'CPU',payload['cpu_percent'],'RAM',payload['ram_percent'])
   if r.ok:
    try: interval=max(15,min(3600,int(r.json().get('monitoring_interval_seconds',interval))))
    except Exception: pass
  except Exception as e:print('heartbeat error:',e)
  # drain max 3 jobs per cycle
  for _ in range(3):
   try:
    url=c['server_url'].rsplit('/heartbeat',1)[0]; r=requests.get(url+'/jobs/next',params={'agent_id':agent_id()},headers={'X-API-Key':c['api_key']},timeout=8)
    if r.status_code!=200:break
    j=r.json().get('job')
    if not j:break
    try:res=run_action(j['action'],j.get('params') or {});ok=True
    except Exception as e:res={'error':str(e)};ok=False
    requests.post(url+f"/jobs/{j['id']}/result",json={'ok':ok,'result':res},headers={'X-API-Key':c['api_key']},timeout=30)
    print(time.strftime('%H:%M:%S'),'action',j['action'],'ok' if ok else 'failed')
   except Exception as e:print('job polling error:',e);break
  time.sleep(interval)
if __name__=='__main__':main()
