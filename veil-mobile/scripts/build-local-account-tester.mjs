import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Local tester only. Signing values come from the process environment; never printed.
const mobile=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'), repo=path.dirname(mobile);
const git=(...args)=>execFileSync('git',args,{cwd:repo,encoding:'utf8',windowsHide:true,maxBuffer:32*1024*1024});
const hash=value=>createHash('sha256').update(value).digest('hex');
function snapshot() {
  const files=[...new Set((git('ls-files','--','veil-mobile')+'\n'+git('ls-files','--others','--exclude-standard','--','veil-mobile')).split(/\r?\n/).filter(Boolean))].sort();
  const entries=Object.fromEntries(files.map(file=>[file,fs.existsSync(path.join(repo,file))?hash(fs.readFileSync(path.join(repo,file))):null]));
  return {baseCommit:git('rev-parse','HEAD').trim(),sourceSnapshotSha256:hash(JSON.stringify(entries)),files:entries};
}
for(const key of ['VEIL_ANDROID_TESTER_KEYSTORE','VEIL_ANDROID_TESTER_KEYSTORE_PASSWORD','VEIL_ANDROID_TESTER_KEY_ALIAS','VEIL_ANDROID_TESTER_KEY_PASSWORD'])
  if(!process.env[key])throw Error('Independent tester signing environment is incomplete');
const versionCode=process.env.VEIL_ANDROID_TESTER_VERSION_CODE, versionName=process.env.VEIL_ANDROID_TESTER_VERSION_NAME;
if(!/^[1-9]\d{0,9}$/.test(versionCode??'')||!/^0\.1\.0-tester\.[\w.-]+$/.test(versionName??''))throw Error('Explicit tester version required');
const start=snapshot();
const java=process.env.JAVA_HOME?path.join(process.env.JAVA_HOME,'bin',process.platform==='win32'?'java.exe':'java'):'java';
const env={...process.env,VEIL_SOURCE_COMMIT:start.baseCommit};
const extra=process.argv.slice(2);
if(extra.some(arg=>/publish|install|uninstall|upload/i.test(arg)))throw Error('Build-only helper');
const child=spawn(java,['-classpath','gradle/wrapper/gradle-wrapper.jar','org.gradle.wrapper.GradleWrapperMain',':app:assembleInternalTester','--no-daemon','--max-workers=2','--console=plain',...extra],{cwd:path.join(mobile,'android'),env,stdio:'inherit',windowsHide:true});
child.on('error',()=>{console.error('Local tester build could not start');process.exitCode=1;});
child.on('exit',code=>{
  process.exitCode=code??1;if(code!==0)return;
  const end=snapshot();if(end.sourceSnapshotSha256!==start.sourceSnapshotSha256||end.baseCommit!==start.baseCommit)throw Error('Source changed during build');
  const apk=path.join(mobile,'android/app/build/outputs/apk/internalTester/app-internalTester.apk');
  const evidence={...start,uncommittedSourceSnapshot:true,versionCode,versionName,apkSha256:hash(fs.readFileSync(apk)),authenticatedE2EVerified:false};
  fs.writeFileSync(apk+'.source-snapshot.json',JSON.stringify(evidence,null,2)+'\n');
  console.log('Tester APK assembled with a separate source snapshot. Base commit alone does not represent local edits. Run the APK verifier before installation.');
});
