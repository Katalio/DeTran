<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.0//EN'>
<!--Router UICopyright (C) 2012-2012 fyang
-->
<html>
<head>
<meta http-equiv='content-type' content='text/html;charset=utf-8'>
<meta name='robots' content='noindex,nofollow'>
<title><% ident(); %> <%translate("Forwarding");%>:<%translate("cloudAXS");%></title>
<link rel='stylesheet' type='text/css' href='common.css'>
<link rel='stylesheet' type='text/css' href='Detran.css'>
<script type='text/javascript' src='common.js'></script>
<script type='text/javascript' src='interfaces.js'></script>
<!-- / / / -->

<style type='text/css'>

#spin {
	visibility: hidden;
	vertical-align: middle;
}
</style>
<script type='text/javascript' src='debug.js'></script>

<script type='text/javascript' src='md5.js'></script>
<script type='text/javascript' src='wireless.jsx?_http_id=<% nv(http_id); %>'></script>
<script type='text/javascript' src='interfaces.js'></script>
<script type='text/javascript'>
//	<% nvram("cloud_server_domain,data_usage_on_cbox,cloud_server_port,cloudAXS_mode,cloud_account_id,cloud_heartbeat_intval,sys_information_on_cbox,net_information_on_cbox,gps_information_on_cbox,sysinfo_checkbox1,sysinfo_checkbox2,sysinfo_checkbox3,sysinfo_checkbox4,sysinfo_checkbox5,sysinfo_checkbox6,netinfo_checkbox1,netinfo_checkbox2,netinfo_checkbox3,netinfo_checkbox4,netinfo_checkbox5,netinfo_checkbox6,netinfo_checkbox7,netinfo_checkbox8,netinfo_checkbox9,netinfo_checkbox10,netinfo_checkbox11,netinfo_checkbox12,netinfo_checkbox13,netinfo_checkbox14,netinfo_checkbox15,data_usage_checkbox1,data_usage_checkbox2,data_usage_checkbox3,data_usage_checkbox4")%>

function verifyFields(focused, quiet)
{
	var i;
	var ok = 1;
	var a, b, c;

	var vis = {
		_f_cloudAXS_mode: 1,
		_f_sys_information_on_cbox: 1,
		_f_net_information_on_cbox: 1,
		_f_gps_information_on_cbox: 1,
		_f_data_usage_on_cbox: 1

		/*_f_sysinfo_checkbox1: 1,
		_f_sysinfo_checkbox2: 1,
		_f_sysinfo_checkbox3: 1,
		_f_sysinfo_checkbox4: 1,
		_f_sysinfo_checkbox5: 1,
		_f_sysinfo_checkbox6: 1,
		_f_netinfo_checkbox1: 1,
		_f_netinfo_checkbox2: 1,
		_f_netinfo_checkbox3: 1,
		_f_netinfo_checkbox4: 1,
		_f_netinfo_checkbox5: 1,
		_f_netinfo_checkbox6: 1,
		_f_netinfo_checkbox7: 1,
		_f_netinfo_checkbox8: 1,
		_f_netinfo_checkbox9: 1,
		_f_netinfo_checkbox10: 1,
		_f_netinfo_checkbox11: 1,
		_f_netinfo_checkbox12: 1,
		_f_netinfo_checkbox13: 1,
		_f_netinfo_checkbox14: 1,
		_f_netinfo_checkbox15: 1,
		_f_data_usage_checkbox1: 1,
		_f_data_usage_checkbox2: 1,
		_f_data_usage_checkbox3: 1,
		_f_data_usage_checkbox4: 1*/
	};
	/*var s = E('_f_sys_information_on_cbox').checked;
	vis._f_sysinfo_checkbox1 = s;
	vis._f_sysinfo_checkbox2 = s;
	vis._f_sysinfo_checkbox3 = s;
	vis._f_sysinfo_checkbox4 = s;
	vis._f_sysinfo_checkbox5 = s;
	vis._f_sysinfo_checkbox6 = s;
	var m = E('_f_net_information_on_cbox').checked;
	vis._f_netinfo_checkbox1 = m;
	vis._f_netinfo_checkbox2 = m;
	vis._f_netinfo_checkbox3 = m;
	vis._f_netinfo_checkbox4 = m;
	vis._f_netinfo_checkbox5 = m;
	vis._f_netinfo_checkbox6 = m;
	vis._f_netinfo_checkbox7 = m;
	vis._f_netinfo_checkbox8 = m;
	vis._f_netinfo_checkbox9 = m;
	vis._f_netinfo_checkbox10 = m;
	vis._f_netinfo_checkbox11 = m;
	vis._f_netinfo_checkbox12 = m;
	vis._f_netinfo_checkbox13 = m;
	vis._f_netinfo_checkbox14 = m;
	vis._f_netinfo_checkbox15 = m;
	var n = E('_f_data_usage_on_cbox').checked;
	vis._f_data_usage_checkbox1 = n;
	vis._f_data_usage_checkbox2 = n;
	vis._f_data_usage_checkbox3 = n;
	vis._f_data_usage_checkbox4 = n;*/
	
	var main_off = E('_f_cloudAXS_mode').checked;
	E('_f_sys_information_on_cbox').disabled = !main_off;
	/*var e = 'sysinfo_checkbox';
	for(i = 0; i < 6; i++)
	{
		var p = '';
	
		p = '_f_' + e + (i + 1);
		E(p).disabled = !main_off;		
	}*/
	E('_f_net_information_on_cbox').disabled = !main_off;
	/*var f = 'netinfo_checkbox';
	for(i = 0; i < 15; i++)
	{
		var p = '';
	
		p = '_f_' + f + (i + 1);
		E(p).disabled = !main_off;		
	}*/
	E('_f_gps_information_on_cbox').disabled = !main_off;
	E('_f_data_usage_on_cbox').disabled = !main_off;
	/*var g = 'data_usage_checkbox';
	for(i = 0; i < 4; i++)
	{
		var p = '';
	
		p = '_f_' + g + (i + 1);
		E(p).disabled = !main_off;		
	}*/
	
	E('_cloud_account_id').disabled = !main_off;
	E('_cloud_heartbeat_intval').disabled = !main_off;
	E('_cloud_server_domain').disabled = !main_off;
	E('_cloud_server_port').disabled = !main_off;

	for (a in vis) {
		b = E(a);
		c = vis[a];
		//b.disabled = (c != 1);
		PR(b).style.display = c ? '' : 'none';
	}
	a = [['_cloud_heartbeat_intval', 0, 1440]];
	for (i = a.length - 1; i >= 0; --i) {
		v = a[i];
		if ((!v_range(v[0], quiet || !ok, v[1], v[2]))) ok = 0;
	}
	
	return ok;
}


function earlyInit()
{
	verifyFields(null, 1);
}

function save()
{
	if (!verifyFields(null, false)) return;

	var fom = E('_fom');

	fom.cloudAXS_mode.value = E('_f_cloudAXS_mode').checked ? 1 : 0;
	fom.sys_information_on_cbox.value = E('_f_sys_information_on_cbox').checked ? 1 : 0;
	fom.net_information_on_cbox.value = E('_f_net_information_on_cbox').checked ? 1 : 0;
	fom.gps_information_on_cbox.value = E('_f_gps_information_on_cbox').checked ? 1 : 0;
	fom.data_usage_on_cbox.value = E('_f_data_usage_on_cbox').checked ? 1 : 0;
	
/*	fom.sysinfo_checkbox1.value = E('_f_sysinfo_checkbox1').checked ? 1 : 0;
	fom.sysinfo_checkbox2.value = E('_f_sysinfo_checkbox2').checked ? 1 : 0;
	fom.sysinfo_checkbox3.value = E('_f_sysinfo_checkbox3').checked ? 1 : 0;
	fom.sysinfo_checkbox4.value = E('_f_sysinfo_checkbox4').checked ? 1 : 0;
	fom.sysinfo_checkbox5.value = E('_f_sysinfo_checkbox5').checked ? 1 : 0;
	fom.sysinfo_checkbox6.value = E('_f_sysinfo_checkbox6').checked ? 1 : 0;
	
	fom.netinfo_checkbox1.value = E('_f_netinfo_checkbox1').checked ? 1 : 0;
	fom.netinfo_checkbox2.value = E('_f_netinfo_checkbox2').checked ? 1 : 0;
	fom.netinfo_checkbox3.value = E('_f_netinfo_checkbox3').checked ? 1 : 0;
	fom.netinfo_checkbox4.value = E('_f_netinfo_checkbox4').checked ? 1 : 0;
	fom.netinfo_checkbox5.value = E('_f_netinfo_checkbox5').checked ? 1 : 0;
	fom.netinfo_checkbox6.value = E('_f_netinfo_checkbox6').checked ? 1 : 0;
	fom.netinfo_checkbox7.value = E('_f_netinfo_checkbox7').checked ? 1 : 0;
	fom.netinfo_checkbox8.value = E('_f_netinfo_checkbox8').checked ? 1 : 0;
	fom.netinfo_checkbox9.value = E('_f_netinfo_checkbox9').checked ? 1 : 0;
	fom.netinfo_checkbox10.value = E('_f_netinfo_checkbox10').checked ? 1 : 0;
	fom.netinfo_checkbox11.value = E('_f_netinfo_checkbox11').checked ? 1 : 0;
	fom.netinfo_checkbox12.value = E('_f_netinfo_checkbox12').checked ? 1 : 0;
	fom.netinfo_checkbox13.value = E('_f_netinfo_checkbox13').checked ? 1 : 0;
	fom.netinfo_checkbox14.value = E('_f_netinfo_checkbox14').checked ? 1 : 0;
	fom.netinfo_checkbox15.value = E('_f_netinfo_checkbox15').checked ? 1 : 0;
	
	fom.data_usage_checkbox1.value = E('_f_data_usage_checkbox1').checked ? 1 : 0;
	fom.data_usage_checkbox2.value = E('_f_data_usage_checkbox2').checked ? 1 : 0;
	fom.data_usage_checkbox3.value = E('_f_data_usage_checkbox3').checked ? 1 : 0;
	fom.data_usage_checkbox4.value = E('_f_data_usage_checkbox4').checked ? 1 : 0;*/
	form.submit(fom, 1);

}

function init()
{
}
</script>

</head>
<body onload='init()'>
<form id='_fom' method='post' action='tomato.cgi'>
<table id='container' cellspacing=0>
<tr><td colspan=2 id='header'>
<div class='title'><% router_pid(); %></div>
</td></tr>
<tr id='body'><td id='navi'><script type='text/javascript'>navi()</script></td>
<td id='content'>
<div id='ident'><% ident(); %></div>

<!-- / / / -->

<input type='hidden' name='_nextpage' >
<input type='hidden' name='_nextwait' >
<input type='hidden' name='_service' value='cloudAXS-restart'>
<input type='hidden' name='_moveip' value='1'>
<input type='hidden' name='_reboot' value='0'>
<input type='hidden' name='cloudAXS_mode'>
<input type='hidden' name='sys_information_on_cbox'>
<input type='hidden' name='net_information_on_cbox'>
<input type='hidden' name='gps_information_on_cbox'>
<input type='hidden' name='data_usage_on_cbox'>
<div class='section-title'><%translate("cloudAXS");%></div>
<div class='section'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("Enable");%>', indent: 5, name: 'f_cloudAXS_mode', type: 'checkbox', value: nvram.cloudAXS_mode == '1' },
	{ title: '<%translate("CloudAXS Server/Port"); %>', indent:5, multi: [
                { name: 'cloud_server_domain', type: 'text', maxlen: 63, size: 32, value: nvram.cloud_server_domain, suffix: ':' },
                { name: 'cloud_server_port', type: 'text', maxlen: 10, size: 7, value: nvram.cloud_server_port } ]},
	{ title: '<%translate("Account ID");%>', indent: 5, name: 'cloud_account_id', type: 'text', maxlen: 10, size: 9, suffix: '<i>(<%translate("please enter 10 digits");%>)</i>', value: nvram.cloud_account_id },
	{ title: '<%translate("Heart-Beat Interval");%>', indent: 5, name: 'cloud_heartbeat_intval', type: 'text', maxlen: 5, size: 7, suffix: '<i>(<%translate("seconds");%>)</i>', value: nvram.cloud_heartbeat_intval },
	{ title: '<%translate("System Information");%>', indent: 5, name: 'f_sys_information_on_cbox', type: 'checkbox', value: nvram.sys_information_on_cbox == '1' },
/*	{ title: '<%translate("Router name");%>',  indent: 2, name: 'f_sysinfo_checkbox1', type: 'checkbox', value: nvram.sysinfo_checkbox1 == '1' },
	{ title: '<%translate("Hardware version");%>', indent: 2, name: 'f_sysinfo_checkbox2', type: 'checkbox', value: nvram.sysinfo_checkbox2 == '1' },
	{ title: '<%translate("Firmware version");%>', indent: 2, name: 'f_sysinfo_checkbox3', type: 'checkbox', value: nvram.sysinfo_checkbox3 == '1' },
	{ title: '<%translate("Router time");%>', indent: 2, name: 'f_sysinfo_checkbox4', type: 'checkbox', value: nvram.sysinfo_checkbox4== '1' },
	{ title: '<%translate("Uptime");%>', indent: 2, name: 'f_sysinfo_checkbox5', type: 'checkbox', value: nvram.sysinfo_checkbox5 == '1' },
	{ title: '<%translate("Total/Free Memory");%>', indent: 2, name: 'f_sysinfo_checkbox6', type: 'checkbox', value: nvram.sysinfo_checkbox6 == '1' },*/
	{ title: '<%translate("Network Information");%>', indent: 5, name: 'f_net_information_on_cbox', type: 'checkbox', value: nvram.net_information_on_cbox == '1' },
	/*{ title: '<%translate("Connection type");%>', indent: 2, name: 'f_netinfo_checkbox1', type: 'checkbox', value: nvram.netinfo_checkbox1 == '1' },
	{ title: '<%translate("Mac Address");%>', indent: 2, name: 'f_netinfo_checkbox2', type: 'checkbox', value: nvram.netinfo_checkbox2 == '1' },
	{ title: '<%translate("Modem type");%>', indent: 2, name: 'f_netinfo_checkbox3', type: 'checkbox', value: nvram.netinfo_checkbox3 == '1' },
	{ title: '<%translate("Modem status");%>', indent: 2, name: 'f_netinfo_checkbox4', type: 'checkbox', value: nvram.netinfo_checkbox4 == '1' },
	{ title: '<%translate("USIM select");%>', indent: 2, name: 'f_netinfo_checkbox5', type: 'checkbox', value: nvram.netinfo_checkbox5 == '1' },
	{ title: '<%translate("Cellular ISP");%>', indent: 2, name: 'f_netinfo_checkbox6', type: 'checkbox', value: nvram.netinfo_checkbox6 == '1' },
	{ title: '<%translate("Cellular network");%>', indent: 2, name: 'f_netinfo_checkbox7', type: 'checkbox', value: nvram.netinfo_checkbox7 == '1' },
	{ title: '<%translate("USIM status");%>', indent: 2, name: 'f_netinfo_checkbox8', type: 'checkbox', value: nvram.netinfo_checkbox8 == '1' },
	{ title: '<%translate("CSQ");%>', indent: 2, name: 'f_netinfo_checkbox9', type: 'checkbox', value: nvram.netinfo_checkbox9 == '1' },
	{ title: '<%translate("IP Address");%>', indent: 2, name: 'f_netinfo_checkbox10', type: 'checkbox', value: nvram.netinfo_checkbox10 == '1' },
	{ title: '<%translate("Subnet mask");%>', indent: 2, name: 'f_netinfo_checkbox11', type: 'checkbox', value: nvram.netinfo_checkbox11 == '1' },
	{ title: '<%translate("Default gateway");%>', indent: 2, name: 'f_netinfo_checkbox12', type: 'checkbox', value: nvram.netinfo_checkbox12 == '1' },
	{ title: '<%translate("DNS");%>', indent: 2, name: 'f_netinfo_checkbox13', type: 'checkbox', value: nvram.netinfo_checkbox13 == '1' },
	{ title: '<%translate("Connection status");%>', indent: 2, name: 'f_netinfo_checkbox14', type: 'checkbox', value: nvram.netinfo_checkbox14 == '1' },
	{ title: '<%translate("Connection uptime");%>', indent: 2, name: 'f_netinfo_checkbox15', type: 'checkbox', value: nvram.netinfo_checkbox15 == '1' },*/
	{ title: '<%translate("GPS Information");%>', indent: 5, name: 'f_gps_information_on_cbox', type: 'checkbox', value: nvram.gps_information_on_cbox == '1' },
	{ title: '<%translate("Data usage");%>', indent: 5, name: 'f_data_usage_on_cbox', type: 'checkbox', value: nvram.data_usage_on_cbox == '1' }
	/*{ title: '<%translate("LAN active number of connected devices");%>', indent: 2, name: 'f_data_usage_checkbox1', type: 'checkbox', value: nvram.data_usage_checkbox1 == '1' },
	{ title: '<%translate("WLAN active number of connected devices");%>', indent: 2, name: 'f_data_usage_checkbox2', type: 'checkbox', value: nvram.data_usage_checkbox2 == '1' },
	{ title: '<%translate("Active VPN connections");%>', indent: 2, name: 'f_data_usage_checkbox3', type: 'checkbox', value: nvram.data_usage_checkbox3 == '1' },
	{ title: '<%translate("Total data sent / received");%>', indent: 2, name: 'f_data_usage_checkbox4', type: 'checkbox', value: nvram.data_usage_checkbox4 == '1' }*/
]);

</script>
</div>


<!-- / / / -->

</td></tr>
<tr><td id='footer' colspan=2>
	<span id='footer-msg'></span>
	<input type='button' value='<%translate("Save");%>' id='save-button' onclick='save()'>
	<input type='button' value='<%translate("Cancel");%>' id='cancel-button' onclick='reloadPage();'>

</td></tr>
</table>
</form>
<script type='text/javascript'>earlyInit()</script>
<div style='height:100px'></div>
</body>
</html>
