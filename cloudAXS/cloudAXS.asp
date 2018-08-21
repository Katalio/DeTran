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
//	<% nvram("cloudAXS_on_cbox, account_id, heartbeat_intval, sys_information_on_cbox, net_information_on_cbox, data_usage_on_cbox, router_name_cbox, hardware_version_cbox, firmware_version_cbox, router_time_cbox, uptime_cbox, total_and_free_memory_cbox, connection_type_cbox, mac_addr_cbox, modem_type_cbox, modem_status_cbox, usim_select_cbox, cellular_isp_cbox, cellular_net_cbox, usim_status_cbox, csq_cbox, ip_addr_cbox, subnet_mask_cbox, default_gateway_cbox, dns_cbox, connection_status_cbox, connection_uptime_cbox, lan_active_num_cbox, wlan_active_num_cbox, active_vpn_connections_cbox, total_data_cbox")%>

function verifyFields(focused, quiet)
{
	var i;
	var ok = 1;
	var a, b, c;

	var main_off, sys_info_off, net_info_off, data_off;
	main_off = !E('_cloudAXS_on_cbox').checked;
	
	E('_sys_information_on_cbox').disabled = main_off;
	E('_net_information_on_cbox').disabled = main_off;
	E('_data_usage_on_cbox').disabled = main_off;
	E('_account_id').disabled = main_off;
	E('_heartbeat_intval').disabled = main_off;

	sys_info_off = !E('_sys_information_on_cbox').checked;		
	E('_router_name_cbox').disabled = sys_info_off |main_off;
	E('_hardware_version_cbox').disabled = sys_info_off |main_off;
	E('_firmware_version_cbox').disabled = sys_info_off |main_off;
	E('_router_time_cbox').disabled = sys_info_off |main_off;
	E('_uptime_cbox').disabled = sys_info_off |main_off;
	E('_total_and_free_memory_cbox').disabled = sys_info_off |main_off;

	net_info_off = !E('_net_information_on_cbox').checked;
	E('_connection_type_cbox').disabled = net_info_off |main_off;
	E('_mac_addr_cbox').disabled = net_info_off |main_off;
	E('_modem_type_cbox').disabled = net_info_off |main_off;
	E('_modem_status_cbox').disabled = net_info_off |main_off;
	E('_usim_select_cbox').disabled = net_info_off |main_off;
	E('_cellular_isp_cbox').disabled = net_info_off |main_off;
	E('_cellular_net_cbox').disabled = net_info_off |main_off;
	E('_usim_status_cbox').disabled = net_info_off |main_off;
	E('_csq_cbox').disabled = net_info_off |main_off;
	E('_ip_addr_cbox').disabled = net_info_off |main_off;
	E('_subnet_mask_cbox').disabled = net_info_off |main_off;
	E('_default_gateway_cbox').disabled = net_info_off |main_off;
	E('_dns_cbox').disabled = net_info_off |main_off;
	E('_connection_status_cbox').disabled = net_info_off |main_off;
	E('_connection_uptime_cbox').disabled = net_info_off |main_off;

	data_off = !E('_data_usage_on_cbox').checked;	
	E('_lan_active_num_cbox').disabled = data_off |main_off;
	E('_wlan_active_num_cbox').disabled = data_off |main_off;
	E('_active_vpn_connections_cbox').disabled = data_off |main_off;
	E('_total_data_cbox').disabled = data_off |main_off;
	
	for (a in vis) {
		b = E(a);
		c = vis[a];
		b.disabled = (c != 1);
		PR(b).style.display = c ? '' : 'none';
	}

	a = [['_socket_timeout', 0, 1440], ['_serial_timeout', 0, 1440], ['_heartbeat_intval', 0, 1440], ['_packet_len', 0, 1048]];
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

	fom.debug_enable.value = E('_f_debug_enable').checked ? 1 : 0;
	fom.cache_enable.value = E('_f_cache_enable').checked ? 1 : 0;
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
<input type='hidden' name='_service' value='dtu-restart'>
<input type='hidden' name='_moveip' value='1'>
<input type='hidden' name='_reboot' value='0'>
<input type='hidden' name='cloudAXS_on_cbox'>
<input type='hidden' name='account_id'>
<input type='hidden' name='heartbeat_intval'>
<input type='hidden' name='sys_information_on_cbox'>
<input type='hidden' name='router_name_cbox'>
<input type='hidden' name='hardware_version_cbox'>
<input type='hidden' name='fireware_version_cbox'>
<input type='hidden' name='router_time_cbox'>
<input type='hidden' name='uptime_cbox'>
<input type='hidden' name='total_and_free_memory_cbox'>
<input type='hidden' name='net_information_on_cbox'>
<input type='hidden' name='connection_type_cbox'>
<input type='hidden' name='mac_addr_cbox'>
<input type='hidden' name='modem_type_cbox'>
<input type='hidden' name='modem_status_cbox'>
<input type='hidden' name='usim_select_cbox'>
<input type='hidden' name='cellular_isp_cbox'>
<input type='hidden' name='cellular_net_cbox'>
<input type='hidden' name='usim_status_cbox'>
<input type='hidden' name='csq_cbox'>
<input type='hidden' name='ip_addr_cbox'>
<input type='hidden' name='subnet_mask_cbox'>
<input type='hidden' name='default_gateway_cbox'>
<input type='hidden' name='dns_cbox'>
<input type='hidden' name='connection_status_cbox'>
<input type='hidden' name='connection_uptime_cbox'>
<input type='hidden' name='data_usage_on_cbox'>
<input type='hidden' name='lan_active_num_cbox'>
<input type='hidden' name='wlan_active_num_cbox'>
<input type='hidden' name='active_vpn_connections_cbox'>
<input type='hidden' name='total_data_cbox'>

<div class='section-title'><%translate("cloudAXS");%></div>
<div class='section'>
<script type='text/javascript'>
createFieldTable('', [
	{ title: '<%translate("Enable");%>', indent: 5, name: 'cloudAXS_on_cbox', type: 'checkbox', value: nvram.cloudAXS_on_cbox == '1' },
	{ title: '<%translate("Account ID");%>', indent: 5, name: 'account_id', type: 'text', maxlen: 8, size: 9, suffix: '<i>(<%translate("please enter 8 digits");%>)</i>', value: nvram.account_id },
	{ title: '<%translate("Heart-Beat Interval");%>', indent: 5, name: 'heartbeat_intval', type: 'text', maxlen: 5, size: 7, suffix: '<i>(<%translate("seconds");%>)</i>', value: nvram.heartbeat_intval },
	{ title: '<%translate("System Information");%>', indent: 5, name: 'sys_information_on_cbox', type: 'checkbox', value: nvram.sys_information_on_cbox == '1' },
	{ title: '<%translate("Router name");%>',  name: 'router_name_cbox', type: 'checkbox', value: nvram.router_name_cbox == '1' },
	{ title: '<%translate("Hardware version");%>', name: 'hardware_version_cbox', type: 'checkbox', value: nvram.hardware_version_cbox == '1' },
	{ title: '<%translate("Firmware version");%>', name: 'firmware_version_cbox', type: 'checkbox', value: nvram.firmware_version_cbox == '1' },
	{ title: '<%translate("Router time");%>', name: 'router_time_cbox', type: 'checkbox', value: nvram.router_time_cbox == '1' },
	{ title: '<%translate("Uptime");%>', name: 'uptime_cbox', type: 'checkbox', value: nvram.uptime_cbox == '1' },
	{ title: '<%translate("Total/Free Memory");%>', name: 'total_and_free_memory_cbox', type: 'checkbox', value: nvram.total_and_free_memory_cbox == '1' },
	{ title: '<%translate("Network Information");%>', indent: 5, name: 'net_information_on_cbox', type: 'checkbox', value: nvram.net_information_on_cbox == '1' },
	{ title: '<%translate("Connection type");%>', name: 'connection_type_cbox', type: 'checkbox', value: nvram.connection_type_cbox == '1' },
	{ title: '<%translate("Mac Address");%>', name: 'mac_addr_cbox', type: 'checkbox', value: nvram.mac_addr_cbox == '1' },
	{ title: '<%translate("Modem type");%>', name: 'modem_type_cbox', type: 'checkbox', value: nvram.modem_type_cbox == '1' },
	{ title: '<%translate("Modem status");%>', name: 'modem_status_cbox', type: 'checkbox', value: nvram.modem_status_cbox == '1' },
	{ title: '<%translate("USIM select");%>', name: 'usim_select_cbox', type: 'checkbox', value: nvram.usim_select_cbox == '1' },
	{ title: '<%translate("Cellular ISP");%>', name: 'cellular_isp_cbox', type: 'checkbox', value: nvram.cellular_isp_cbox == '1' },
	{ title: '<%translate("Cellular network");%>', name: 'cellular_net_cbox', type: 'checkbox', value: nvram.cellular_net_cbox == '1' },
	{ title: '<%translate("USIM status");%>', name: 'usim_status_cbox', type: 'checkbox', value: nvram.usim_status_cbox == '1' },
	{ title: '<%translate("CSQ");%>', name: 'csq_cbox', type: 'checkbox', value: nvram.csq_cbox == '1' },
	{ title: '<%translate("IP Address");%>', name: 'ip_addr_cbox', type: 'checkbox', value: nvram.ip_addr_cbox == '1' },
	{ title: '<%translate("Subnet mask");%>', name: 'subnet_mask_cbox', type: 'checkbox', value: nvram.subnet_mask_cbox == '1' },
	{ title: '<%translate("Default gateway");%>', name: 'default_gateway_cbox', type: 'checkbox', value: nvram.default_gateway_cbox == '1' },
	{ title: '<%translate("DNS");%>', name: 'dns_cbox', type: 'checkbox', value: nvram.dns_cbox == '1' },
	{ title: '<%translate("Connection status");%>', name: 'connection_status_cbox', type: 'checkbox', value: nvram.connection_status_cbox == '1' },
	{ title: '<%translate("Connection uptime");%>', name: 'connection_uptime_cbox', type: 'checkbox', value: nvram.connection_uptime_cbox == '1' },
	{ title: '<%translate("Data usage");%>', indent: 5, name: 'data_usage_on_cbox', type: 'checkbox', value: nvram.data_usage_on_cbox == '1' },
	{ title: '<%translate("LAN active number of connected devices");%>', name: 'lan_active_num_cbox', type: 'checkbox', value: nvram.lan_active_num_cbox == '1' },
	{ title: '<%translate("WLAN active number of connected devices");%>', name: 'wlan_active_num_cbox', type: 'checkbox', value: nvram.wlan_active_num_cbox == '1' },
	{ title: '<%translate("Active VPN connections");%>', name: 'active_vpn_connections_cbox', type: 'checkbox', value: nvram.active_vpn_connections_cbox == '1' },
	{ title: '<%translate("Total data sent / received");%>', name: 'total_data_cbox', type: 'checkbox', value: nvram.total_data_cbox == '1' }
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
