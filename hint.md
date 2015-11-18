## table0
table=0, n_packets=11, n_bytes=858, priority=0 actions=goto_table:1
## table1
table=1, n_packets=0, n_bytes=0, priority=0,arp actions=goto_table:2
table=1, n_packets=0, n_bytes=0, priority=0,ip actions=goto_table:3
## table2
table=2, n_packets=0, n_bytes=0, priority=0,arp,in_port=1,arp_tpa=192.168.1.1,arp_op=1 actions=CONTROLLER:65535,move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:01:01:01:01:01:01->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:01:01:01:01:01:01->arp_sha,set_field:192.168.1.1->arp_spa,load:0xffff->OXM_OF_IN_PORT[],load:0x1->NXM_NX_REG1[],goto_table:6
table=2, n_packets=0, n_bytes=0, priority=0,arp,in_port=1,arp_tpa=192.168.1.1,arp_op=2 actions=CONTROLLER:65535
table=2, n_packets=0, n_bytes=0, priority=0,arp,in_port=2,arp_tpa=192.168.2.1,arp_op=1 actions=CONTROLLER:65535,move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],set_field:02:02:02:02:02:02->eth_src,set_field:2->arp_op,move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:02:02:02:02:02:02->arp_sha,set_field:192.168.2.1->arp_spa,load:0xffff->OXM_OF_IN_PORT[],load:0x2->NXM_NX_REG1[],goto_table:6
table=2, n_packets=0, n_bytes=0, priority=0,arp,in_port=2,arp_tpa=192.168.2.1,arp_op=2 actions=CONTROLLER:65535
table=2, n_packets=0, n_bytes=0, priority=0,arp,reg1=0x1 actions=set_field:01:01:01:01:01:01->eth_src,set_field:01:01:01:01:01:01->arp_sha,set_field:192.168.1.1->arp_spa,goto_table:6
table=2, n_packets=0, n_bytes=0, priority=0,arp,reg1=0x2 actions=set_field:02:02:02:02:02:02->eth_src,set_field:02:02:02:02:02:02->arp_sha,set_field:192.168.2.1->arp_spa,goto_table:6
## table3
table=3, n_packets=0, n_bytes=0, priority=40024,ip,nw_dst=192.168.1.0/24 actions=move:NXM_OF_IP_DST[]->NXM_NX_REG0[],goto_table:4
table=3, n_packets=0, n_bytes=0, priority=40024,ip,nw_dst=192.168.2.0/24 actions=move:NXM_OF_IP_DST[]->NXM_NX_REG0[],goto_table:4
table=3, n_packets=0, n_bytes=0, priority=0,ip actions=load:0xc0a80102->NXM_NX_REG0[],goto_table:4
## table4
table=4, n_packets=0, n_bytes=0, priority=0,reg0=0xc0a80100/0xffffff00 actions=load:0x1->NXM_NX_REG1[],set_field:01:01:01:01:01:01->eth_src,goto_table:5
table=4, n_packets=0, n_bytes=0, priority=0,reg0=0xc0a80200/0xffffff00 actions=load:0x2->NXM_NX_REG1[],set_field:02:02:02:02:02:02->eth_src,goto_table:5
## table5
table=5, n_packets=0, n_bytes=0, priority=2,ip,reg0=0xc0a80101 actions=set_field:01:01:01:01:01:01->eth_dst,goto_table:6
table=5, n_packets=0, n_bytes=0, priority=2,ip,reg0=0xc0a80201 actions=set_field:02:02:02:02:02:02->eth_dst,goto_table:6
table=5, n_packets=0, n_bytes=0, priority=1,ip actions=CONTROLLER:65535
## table6
table=6, n_packets=0, n_bytes=0, priority=0 actions=output:NXM_NX_REG1[]
