//<% nvram("lan_device_num,wifi_client_num,total_package_num,total_vpn,lte,router_hw,wan_iface,back_mode,ppp_demand,cellManual,cellConMode,wan_up,modem_imei,modem_imsi,sim_state,sim_ccid,lac_ci,cell_network,cops,sim_flag,modem_type,modem_state,main_remain,backup_remain,csq,ppp_get_ip,pptp_server_ip,router_name,wan_domain,wan_gateway,wan_gateway_get,wan_get_domain,wan_hostname,wan_hwaddr,wan_ipaddr,wan_netmask,wan_proto,wan_run_mtu,et0macaddr,wan_ifnames,wl_mode,vpn_mode,vpn_client_up,vpn_client_rip,vpn_client_lip,ipsec1_esp,ipsec1_ike,ipsec1_mode,ipsec1_ph1,ipsec1_ph2,ipsec1_recv,ipsec1_send,ipsec2_esp,ipsec2_ike,ipsec2_mode,ipsec2_ph1,ipsec2_ph2,ipsec2_recv,ipsec2_send,ipsec1_active,ipsec2_active,cloud_response_code,gps_valid,gps_bds,gps_use,gps_date,gps_time,gps_latitude,gps_NS,gps_longitude,gps_EW"); %>
//<% version(0); %>
//<% uptime(); %>
//<% sysinfo(); %>
//<% dns(); %>

stats = { };

do {
	var a, b, i;
	var xifs = ['wan', 'lan', 'lan1', 'lan2', 'lan3'];

	if (typeof(last_wan_proto) == 'undefined') {
		last_wan_proto = nvram.wan_proto;
	}
	else if (last_wan_proto != nvram.wan_proto) {
		reloadPage();
	}
	stats.firmware = version_d.firmware;
	stats.hardware = version_d.hardware;
	stats.flashsize = sysinfo.flashsize+'MB';
	stats.cpumhz = sysinfo.cpuclk+'MHz';
	stats.systemtype = sysinfo.systemtype;
	stats.cpuload = ((sysinfo.loads[0] / 65536.0).toFixed(2) + '<small> / </small> ' +
		(sysinfo.loads[1] / 65536.0).toFixed(2) + '<small> / </small>' +
		(sysinfo.loads[2] / 65536.0).toFixed(2));
	stats.uptime = sysinfo.uptime_s;

	a = sysinfo.totalram;
	b = sysinfo.totalfreeram;
	stats.memory = scaleSize(a) + ' / ' + scaleSize(b) + ' <small>(' + (b / a * 100.0).toFixed(2) + '%)</small>';
	if (sysinfo.totalswap > 0) {
		a = sysinfo.totalswap;
		b = sysinfo.freeswap;
		stats.swap = scaleSize(a) + ' / ' + scaleSize(b) + ' <small>(' + (b / a * 100.0).toFixed(2) + '%)</small>';
	} else
		stats.swap = '';


	stats.wanup = nvram.wan_up;

		
	stats.modem_imei = nvram.modem_imei;
	if (nvram.csq == 99 || nvram.csq == 199)
		stats.csq = 0;
	else
		stats.csq = nvram.csq;
		
	
	if(stats.csq > 100)
	{
		stats.csq_r = (stats.csq - 100)+'%';
		stats.csq += ' <img src="bar' + MIN(MAX(Math.floor((stats.csq - 100) / 16), 1), 6) + '.gif">' + ' ( '+stats.csq_r+' ) ';
	}
	else
	{
		stats.csq_r = Math.floor((stats.csq*100)/31)+'%';
		stats.csq += ' <img src="bar' + MIN(MAX(Math.floor(stats.csq / 5), 1), 6) + '.gif">' + ' ( '+stats.csq_r+' ) ';
	}		
	if(nvram.cell_network == '')
		stats.cell_network = "";
	else
		stats.cell_network = nvram.cell_network;
		
	stats.lac_ci = nvram.lac_ci;
	stats.cops = nvram.cops;
	
	stats.main_remain = nvram.main_remain;
	stats.backup_remain = nvram.backup_remain;

	stats.gps_valid = nvram.gps_valid;
	stats.gps_bds = nvram.gps_bds;
	stats.gps_use = nvram.gps_use;
	stats.gps_use += ' <img src="bar' + MIN(MAX(Math.floor(nvram.gps_use / 2), 1), 6) + '.gif">';
	stats.gps_date = nvram.gps_date + ' - ' + nvram.gps_time;
	stats.gps_mesg = nvram.gps_latitude + nvram.gps_NS + ' - ' + nvram.gps_longitude + nvram.gps_EW;
	
	stats.wanip = nvram.wan_ipaddr;
	stats.backup_mode = nvram.backup_mode;
	stats.wannetmask = nvram.wan_netmask;
	stats.wangateway = nvram.wan_gateway_get;
	if (stats.wangateway == '0.0.0.0' || stats.wangateway == '')
		stats.wangateway = nvram.wan_gateway;

	if (stats.wanup != '1') {
		stats.wanip = '0.0.0.0';
		stats.wannetmask = '0.0.0.0';
		stats.wangateway = '0.0.0.0';
	}
	if (dns != '')
		stats.dns = dns.join(', ');
	else
		stats.dns = '0.0.0.0';
	
  if (stats.wanup == '1') 
    stats.wanstatus = '<b>Connected</b>';
  else 
    stats.wanstatus = '<b>Disconnected</b>';
	
	stats.time = '<% time(); %>';
	if (stats.wanup == '1')
		stats.wanuptime = '<% link_uptime(); %>';
	else
		stats.wanuptime = '';

	  stats.vpn_mode = nvram.vpn_mode;
	  stats.vpn_client_up = nvram.vpn_client_up;
	  stats.vpn_client_lip = nvram.vpn_client_lip;
	  stats.vpn_client_rip = nvram.vpn_client_rip;  
	if (nvram.ipsec1_mode == '1' && nvram.ipsec1_active== '1')
	{
		stats.ipsec1_mode = 'Enable';
		stats.ipsec1_ph1 = nvram.ipsec1_ph1;
		stats.ipsec1_ike = nvram.ipsec1_ike;
		stats.ipsec1_ph2 = nvram.ipsec1_ph2;
		stats.ipsec1_esp = nvram.ipsec1_esp;
		stats.ipsec1_recv = '&nbsp;&nbsp;' + nvram.ipsec1_recv + '<small>Bytes</small>';
		stats.ipsec1_send = '&nbsp;&nbsp;' + nvram.ipsec1_send + '<small>Bytes</small>';
	}
	else
	{
		stats.ipsec1_mode = 'Disable';
	}
	if (nvram.ipsec2_mode == '1' && nvram.ipsec2_active== '1')
	{
		stats.ipsec2_mode = 'Enable';
		stats.ipsec2_ph1 = nvram.ipsec2_ph1;
		stats.ipsec2_ike = nvram.ipsec2_ike;
		stats.ipsec2_ph2 = nvram.ipsec2_ph2;
		stats.ipsec2_esp = nvram.ipsec2_esp;
		stats.ipsec2_recv = '&nbsp;&nbsp;' + nvram.ipsec2_recv + '<small>Bytes</small>';
		stats.ipsec2_send = '&nbsp;&nbsp;' + nvram.ipsec2_send + '<small>Bytes</small>';
	}
	else
	{
		stats.ipsec2_mode = 'Disable';
	}
	

		if (!stats.wanup0) {
			stats.wanip0 = '0.0.0.0';
			stats.wannetmask0 = '0.0.0.0';
			stats.wangateway0 = '0.0.0.0';
		}
		if (!stats.wanup1) {
			stats.wanip1 = '0.0.0.0';
			stats.wannetmask1 = '0.0.0.0';
			stats.wangateway1 = '0.0.0.0';
		}
		if (!stats.wanup2) {
			stats.wanip2 = '0.0.0.0';
			stats.wannetmask2 = '0.0.0.0';
			stats.wangateway2 = '0.0.0.0';
		}
	
	stats.wanstatus = '<% wanstatus(); %>';
	if (stats.wanstatus != 'Connected') stats.wanstatus = '<b>' + stats.wanstatus + '</b>';
	if (stats.vpn_client_up == "1") 
	    stats.vpn_client_up = 'Connected';
	else 
	    stats.vpn_client_up = 'Disconnected';
} while (0);

