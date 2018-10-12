<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML 4.0//EN'>
<!--Router UICopyright (C) 2012-2012 fyang
-->
<html>
<head>
<meta http-equiv='content-type' content='text/html;charset=utf-8'>
<meta name='robots' content='noindex,nofollow'>
<meta http-equiv="refresh" content="10">
<title><% ident(); %> <%translate("Status");%>: <%translate("Overview");%></title>
<link rel='stylesheet' type='text/css' href='common.css'>
<link rel='stylesheet' type='text/css' href='Detran.css'>
<script type='text/javascript' src='common.js'></script>
<script type='text/javascript' src='interfaces.js'></script>

<!-- / / / -->

<style type='text/css'>
.controls {
	width: 90px;
	margin-top: 5px;
	margin-bottom: 10px;
}
</style>
<script type='text/javascript' src='status-data-sys.jsx?_http_id=<% nv(http_id); %>'></script>

<script type='text/javascript'>
show_dhcpc = ((nvram.wan_proto == 'dhcp') || (((nvram.wan_proto == 'l2tp') || (nvram.wan_proto == 'pptp')) && (nvram.pptp_dhcp == '1')));
show_codi = ((nvram.wan_proto == 'pppoe') || (nvram.wan_proto == 'l2tp') || (nvram.wan_proto == 'pptp') || (nvram.wan_proto == 'ppp3g'));

function dhcpc(what)
{
	form.submitHidden('dhcpc.cgi', { exec: what, _redirect: 'status-overview.asp' });
}

function serv(service, sleep)
{
	form.submitHidden('service.cgi', { _service: service, _redirect: 'status-overview.asp', _sleep: sleep });
}
function b_synctime()
{
	var currentTime = new Date();

	var seconds = currentTime.getSeconds();
	var minutes = currentTime.getMinutes();
	var hours = currentTime.getHours();
	var month = currentTime.getMonth() + 1;
	var day = currentTime.getDate();
	var year = currentTime.getFullYear();

	var seconds_str = " ";
	var minutes_str = " ";
	var hours_str = " ";
	var month_str = " ";
	var day_str = " ";
	var year_str = " ";

	if(seconds < 10)
		seconds_str = "0" + seconds;
	else
		seconds_str = ""+seconds;

	if(minutes < 10)
		minutes_str = "0" + minutes;
	else
		minutes_str = ""+minutes;

	if(hours < 10)
		hours_str = "0" + hours;
	else
		hours_str = ""+hours;

	if(month < 10)
		month_str = "0" + month;
	else
		month_str = ""+month;

	if(day < 10)
		day_str = "0" + day;
	else
		day_str = day;

	var tmp = year + "-" + month_str + "-" + day_str + " " + hours_str + ":" + minutes_str + ":" + seconds_str;
	
	form.submitHidden('service.cgi', { _service: 'sync_time', _redirect: 'status-overview.asp', _sleep: 5, _time: tmp });
}

function wan_connect()
{
	serv('cellManual-up', 12);
}

function wan_disconnect()
{
	serv('cellManual-down', 12);
}
var ref = new DetranRefresh('status-data-sys.jsx', '', 0, 'status_overview_refresh');
ref.refresh = function(text)
{
	stats = {};
	try {
		eval(text);
	}
	catch (ex) {
		stats = {};
	}
	show();
}


function c(id, htm)
{
	E(id).cells[1].innerHTML = htm;
}

function show()
{
	stats.modem_state = (nvram.modem_state == "1")?'<b><%translate("Ready");%></b>':(nvram.modem_state == "0")?'<b><%translate("Unknown");%></b>':'<b><span style="color:red"><%translate("Searching");%>...</span></b>';
	//stats.sim_selected = (nvram.sim_flag == "2")?'<b><%translate("USIM 2 Running");%></b>':(nvram.sim_flag== "1")?'<b><%translate("USIM 1 Running");%></b>':'<b><span style="color:red"><%translate("Searching");%>...</span></b>';
	stats.sim_selected = (nvram.wan_ifnameX == "vlan1")?'<b><%translate("WAN Running");%></b>' : (nvram.sim_flag == "2")?'<b><%translate("USIM 2 Running");%></b>':'<b><%translate("USIM 1 Running");%></b>';
	stats.sim_state = (nvram.sim_state == "1")?'<b><%translate("Ready");%></b>':(nvram.sim_state == "0")?'<b><%translate("Unknown");%></b>':'<b><span style="color:red"><%translate("Searching");%>...</span></b>';
	stats.time += ' <input type="button" value="<%translate("Clock Sync.");%>" onclick="b_synctime()">';
	c('firmware', stats.firmware);
	c('hardware', stats.hardware);
	c('cpu', stats.cpuload);
	c('uptime', stats.uptime);
	c('time', stats.time);
	c('modem_state', stats.modem_state);
	c('sim_selected', stats.sim_selected);
	c('cell_network', stats.cell_network);
	c('cops', stats.cops);
	c('sim_state', stats.sim_state);
	c('csq', stats.csq);
	c('lac_ci', stats.lac_ci);
	c('wanip', stats.wanip);
	c('wannetmask', stats.wannetmask);
	c('wangateway', stats.wangateway);
	c('dns', stats.dns);
	c('vpn_mode', stats.vpn_mode);
	c('vpn_client_up', stats.vpn_client_up);
	c('vpn_client_lip', stats.vpn_client_lip);
	c('vpn_client_rip', stats.vpn_client_rip);
	c('memory', stats.memory);
	c('swap', stats.swap);
	if( stats.ipsec1_mode == 'Enable')
	{
		c('ipsec1_mode', stats.ipsec1_mode);
		c('ipsec1_ph1', stats.ipsec1_ph1);
		c('ipsec1_ike', stats.ipsec1_ike);
		c('ipsec1_ph2', stats.ipsec1_ph2);
		c('ipsec1_esp', stats.ipsec1_esp);
		c('ipsec1_recv', stats.ipsec1_recv);
		c('ipsec1_send', stats.ipsec1_send);
	}
	if( stats.ipsec2_mode == 'Enable')
	{
		c('ipsec2_mode', stats.ipsec2_mode);
		c('ipsec2_ph1', stats.ipsec2_ph1);
		c('ipsec2_ike', stats.ipsec2_ike);
		c('ipsec2_ph2', stats.ipsec2_ph2);
		c('ipsec2_esp', stats.ipsec2_esp);
		c('ipsec2_recv', stats.ipsec2_recv);
		c('ipsec2_send', stats.ipsec2_send);
	}

	elem.display('swap', stats.swap != '');
	elem.display('mac', nvram.wan_proto!='ppp3g');
	elem.display('imei', (nvram.wan_proto=='ppp3g')||(nvram.lte=='1'));
	elem.display('modem_state', (nvram.wan_proto=='ppp3g')||(nvram.lte=='1'));
	elem.display('sim_state', (nvram.wan_proto=='ppp3g')||(nvram.lte=='1'));
	elem.display('sim_ccid', (nvram.wan_proto=='ppp3g')||(nvram.lte=='1'));
	elem.display('csq', (nvram.wan_proto=='ppp3g')||(nvram.lte=='1'));
	c('wanstatus', stats.wanstatus);
	c('wanuptime', stats.wanuptime);
	c('main_remain', stats.main_remain);
	c('backup_remain', stats.backup_remain);

	c('gps_valid', stats.gps_valid);
	c('gps_bds', stats.gps_bds);
	c('gps_use', stats.gps_use);
	c('gps_date', stats.gps_date);
	c('gps_mesg', stats.gps_mesg);

	if (show_dhcpc && (nvram.lte!='1')) c('wanlease', stats.wanlease);
	if (show_codi) {
		E('b_connect').disabled = stats.wanup;
		E('b_disconnect').disabled = !stats.wanup;
	}

}

function earlyInit()
{
	elem.display('b_dhcpc', show_dhcpc&&(nvram.lte!='1'));
	if(nvram.ppp_demand == 4)
		elem.display('b_connect', 'b_disconnect', show_codi);
	if (nvram.wan_proto == 'disabled')
		elem.display('wan-title', 'sesdiv_wan', 0);
	show();
}

function init()
{
	var c;
	if (((c = cookie.get('status_overview_system_vis')) != null) && (c != '1')) toggleVisibility("system");
	if (((c = cookie.get('status_overview_wan_vis')) != null) && (c != '1')) toggleVisibility("wan");
	ref.initPage(3000, 3);
}

function toggleVisibility(whichone) {
	if (E('sesdiv_' + whichone).style.display == '') {
		E('sesdiv_' + whichone).style.display = 'none';
		E('sesdiv_' + whichone + '_showhide').innerHTML = '(show)';
		cookie.set('status_overview_' + whichone + '_vis', 0);
	} else {
		E('sesdiv_' + whichone).style.display='';
		E('sesdiv_' + whichone + '_showhide').innerHTML = '(hide)';
		cookie.set('status_overview_' + whichone + '_vis', 1);
	}
}

</script>

</head>
<body onload='init()'>
<form>
<table id='container' cellspacing=0>
<tr><td colspan=2 id='header'>
<div class='title'><% router_pid(); %></div>
</td></tr>
<tr id='body'><td id='navi'><script type='text/javascript'>navi()</script></td>
<td id='content'>
<div id='ident'><% ident(); %></div>

<!-- / / / -->

<div class='section-title'><%translate("System Information");%></div>
<div class='section' id='sesdiv_system'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("Router Name");%>', text: nvram.router_name},
	{ title: '<%translate("Hardware Version");%>', text: nvram.router_hw },
	//{ title: '<%translate("Hardware Version");%>', rid:'hardware', text: stats.hardwave },
	{ title: '<%translate("Firmware Version");%>', rid:'firmware', text: stats.firmwave },
	{ title: '<%translate("CPU Freq");%>', text: stats.cpumhz, hidden:1 },
	{ title: '<%translate("Flash Size");%>', text: stats.flashsize, hidden:1 },
	{ title: '<%translate("Router Time");%>', rid: 'time', text: stats.time },
	{ title: '<%translate("Uptime");%>', rid: 'uptime', text: stats.uptime },
	{ title: '<%translate("CPU Load");%> <small>(1 / 5 / 15 <%translate("minute");%>)</small>', rid: 'cpu', text: stats.cpuload, hidden:1 },
	{ title: '<%translate("Total / Free Memory");%>', rid: 'memory', text: stats.memory },
	{ title: '<%translate("Total / Free Swap");%>', rid: 'swap', text: stats.swap, hidden: (stats.swap == '') }
]);
</script>
</div>

<div class='section-title' id='wan-title'><%translate("Network Information");%></div>
<div class='section' id='sesdiv_wan'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("Connection Type");%>', text: { 'usb0':'<%translate("Cellular Network");%>', 'ppp0':'<%translate("Cellular Network");%>', 'vlan1':'<%translate("WAN");%>', 'eth1':'<%translate("WiFi");%>'  }[nvram.wan_iface]},
	{ title: '<%translate("MAC Address");%>', rid: 'mac', text: nvram.wan_hwaddr },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp': 'TDD-LTE(ZTE ME3760)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden:((nvram.lte=='1'&&nvram.modem_type=='ME3760:LTE/WCDMA/TD-SCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(U9300)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden:((nvram.lte=='1'&&nvram.modem_type=='U9300:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(U8300)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden:((nvram.lte=='1'&&nvram.modem_type=='U8300:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'FDD-LTE(Sierra MC73xx)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='MC73xx:WCDMA/HSPA+/FDD-LTE')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'LTE(Huawei ME90X)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='ME90X:LTE/HSPA+/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(SIMCOM SIM7230E)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='SIM7230E:FDD-LTE/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(SIMCOM SIM7230E-N)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='SIM72XX/71XX:FDD-LTE/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(Signal SLM630)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='SLM630:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(Signal SLM7XX)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='SLM7XX:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(NODECOM NL6XX)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='NL6XX:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(ZTE ME3620)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='ME3620:LTE/WCDMA/TD-SCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'FDD-LTE(ZTE ZM8620)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='ZM8620:LTE/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(Quectel EC2X)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='EC25:LTE/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'TDD/FDD-LTE(Quectel EC20)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='EC20:FDD-LTE/TDD-LTE/TD-SCDMA/WCDMA')? 0:1) },
	{ title: '<%translate("Modem Type");%>', text: { 'dhcp':'FDD-LTE(Telit LE910)', 'static':'<%translate("Static");%> IP', 'pppoe':'PPPoE', 'pptp':'PPTP', 'l2tp':'L2TP', 'ppp3g':'' }[nvram.wan_proto]+((nvram.wan_proto=='ppp3g')?nvram.modem_type:'')+(((nvram.wan_proto=='dhcp')&&(nvram.wl_mode=='sta'))?'(WiFi Client)':'') || '-', hidden: ((nvram.lte=='1'&&nvram.modem_type=='LE910:LTE/WCDMA/HSPA+')? 0:1) },
	{ title: 'Modem Type', text: '3G-'+nvram.modem_type, hidden: ((nvram.lte!='1')? 0:1) },
	{ title: 'Modem IMEI', rid: 'imei', text: nvram.modem_imei },
	{ title: '<%translate("Modem Status");%>', rid: 'modem_state', text: stats.modem_state },
	{ title: '<%translate("USIM Select");%>', rid: 'sim_selected', text: stats.sim_selected },
	{ title: '<%translate("Cellular ISP");%>', rid: 'cops', text: stats.cops },
	{ title: '<%translate("Cellular Network");%>', rid: 'cell_network', text: stats.cell_network },
	{ title: '<%translate("USIM Status");%>', rid: 'sim_state', text: stats.sim_state },
	{ title: '<%translate("USIM ID");%>', rid: 'sim_ccid', text: nvram.sim_ccid, hidden: !(nvram.modem_type == 'EM820U:WCDMA/HSPA+'), hidden: 1 },
	{ title: '<%translate("CSQ");%>', rid: 'csq', text: stats.csq },
	{ title: 'LAC', rid: 'lac_ci', text: stats.lac_ci, hidden: !(nvram.modem_type == 'ME3760:LTE/WCDMA/TD-SCDMA') },
	{ title: '<%translate("IP Address");%>', rid: 'wanip', text: stats.wanip },
	{ title: '<%translate("Subnet Mask");%>', rid: 'wannetmask', text: stats.wannetmask },
	{ title: '<%translate("Gateway");%>', rid: 'wangateway', text: stats.wangateway },
	{ title: 'DNS', rid: 'dns', text: stats.dns },
	{ title: 'MTU', text: nvram.wan_run_mtu, hidden: 1 },
	{ title: '<%translate("Connection Status");%>', rid: 'wanstatus', text: stats.wanstatus },
	{ title: '<%translate("Connection Uptime");%>', rid: 'wanuptime', text: stats.wanuptime },
	{ title: '<%translate("Main Card Lease Time");%>', rid: 'main_remain', text: stats.main_remain, hidden: 1 },
	{ title: '<%translate("Back Card Lease Time");%>', rid: 'backup_remain', text: stats.backup_remain, hidden: 1 },
	{ title: '<%translate("Remaining Lease Time");%>', rid: 'wanlease', text: stats.wanlease, ignore: !show_dhcpc || (nvram.lte=='1'), hidden: 1 }
]);
</script>


<span id='b_dhcpc' style='display:none'>
	<input type='button' class='controls' onclick='dhcpc("renew")' value='<%translate("Renew");%>'>
	<input type='button' class='controls' onclick='dhcpc("release")' value='<%translate("Release");%>'> &nbsp;
</span>
<input type='button' class='controls' onclick='wan_connect()' value='<%translate("Connect");%>' id='b_connect' style='display:none'>
<input type='button' class='controls' onclick='wan_disconnect()' value='<%translate("Disconnect");%>' id='b_disconnect' style='display:none'>
</div>

<div class='section-title'><%translate("GPS Information");%></div>
<div class='section' id='sesdiv_system'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("GPS Status(Current)");%>', rid: 'gps_valid', text: stats.gps_valid},
	{ title: '<%translate("System Type");%>', rid: 'gps_bds', text: stats.gps_bds },
	{ title: '<%translate("Number of satellites");%>', rid: 'gps_use', text: stats.gps_use },
	{ title: '<%translate("Satellites clock");%>', rid: 'gps_date', text: stats.gps_date},
	{ title: '<%translate("Positioning");%>', rid: 'gps_mesg', text: stats.gps_mesg}
	]);
</script>
</div>

<div class='section-title'><%translate("Data Usage");%></div>
<div class='section' id='sesdiv_system'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("LAN active number of connected devices");%>', text: nvram.lan_device_num},
	{ title: '<%translate("WLAN active number of connected devices");%>', text: nvram.wifi_client_num },
	{ title: '<%translate("Active VPN connections");%>', rid:'firmware', text: nvram.total_vpn },
	{ title: '<%translate("Total data sent / received");%>', text: nvram.total_package_num }
	]);
</script>
</div>

<div class='section-title'><%translate("Server Response");%></div>
<div class='section' id='sesdiv_system'>
<script type='text/javascript'>
createFieldTable('', [
	{ title:'', text: nvram.cloud_response_code}
]);
</script>
</div>

<div class='section' id='sesdiv_vpn'>
<script type='text/javascript'>
	if(( stats.ipsec1_mode == 'Enable') || ( stats.ipsec2_mode == 'Enable'))
	{
		document.write("<div class='section-title' id='wan-title'><%translate('VPN Status');%></div>");
	}
	if( stats.ipsec1_mode == 'Enable')
	{
		createFieldTable('', [
			{ title: 'IPSec 1', rid: 'ipsec1_mode', text: stats.ipsec1_mode },
			{ title: 'Phase 1 Status', rid: 'ipsec1_ph1', indent:2, text: stats.ipsec1_ph1 },
			{ title: 'Phase 1 IKE', rid: 'ipsec1_ike', indent:2, text: stats.ipsec1_ike },
			{ title: 'Phase 2 Status', rid: 'ipsec1_ph2', indent:2, text: stats.ipsec1_ph2 },
			{ title: 'Phase 2 ESP', rid: 'ipsec1_esp', indent:2, text: stats.ipsec1_esp },
			{ title: 'IPSec Recv.', rid: 'ipsec1_recv', indent:2, text: stats.ipsec1_recv },
			{ title: 'IPSec Send.', rid: 'ipsec1_send', indent:2, text: stats.ipsec1_send }
		]);
	}
	if( stats.ipsec2_mode == 'Enable')
	{
		createFieldTable('', [
			{ title: 'IPSec 2', rid: 'ipsec2_mode', text: stats.ipsec2_mode },
			{ title: 'Phase 1 Status', rid: 'ipsec2_ph1', indent:2, text: stats.ipsec2_ph1 },
			{ title: 'Phase 1 IKE', rid: 'ipsec2_ike', indent:2, text: stats.ipsec2_ike },
			{ title: 'Phase 2 Status', rid: 'ipsec2_ph2', indent:2, text: stats.ipsec2_ph2 },
			{ title: 'Phase 2 ESP', rid: 'ipsec2_esp', indent:2, text: stats.ipsec2_esp },
			{ title: 'IPSec Recv.', rid: 'ipsec2_recv', indent:2, text: stats.ipsec2_recv },
			{ title: 'IPSec Send.', rid: 'ipsec2_send', indent:2, text: stats.ipsec2_send }
		]);
}
</script>
</div>



<!-- / / / -->

</td></tr>
<tr><td id='footer' colspan=2>
	<script type='text/javascript'>genStdRefresh(1,0,'ref.toggle()');</script>
/* OEM-BEGIN */
	<br><div class="copy"><%translate("CopyRight");%></div>
/* OEM-END */
</td></tr>
</table>
</form>
<script type='text/javascript'>earlyInit()</script>
</body>
</html>

