require 'arp_table'
require 'interfaces'
require 'routing_table'

# Simple implementation of L3 switch in OpenFlow1.0
class SimpleRouter < Trema::Controller

  INGRESS_TABLE_ID = 0
  CLASSIFIER_TABLE_ID = 1 
  ARP_RESPONDER_TABLE_ID = 2
  ROUTING_TABLE_ID = 3
  INTERFACE_LOOKUP_TABLE_ID = 4
  ARP_LOOKUP_TABLE_ID = 5
  EGRESS_TABLE_ID = 6

  AGING_TIME = 180

  DL_TYPE_IP = 0x0800
  DL_TYPE_ARP = 0x0806

  def start(_args)
    load File.join(__dir__, '..', 'simple_router.conf')
    @interfaces = Interfaces.new(Configuration::INTERFACES)
    @arp_table = ArpTable.new
    @routing_table = RoutingTable.new(Configuration::ROUTES)
    @unresolved_packet_queue = Hash.new { [] }
    logger.info "#{name} started."
  end

  def switch_ready(dpid)
    send_flow_mod_delete(dpid, match: Match.new)
    add_default_ingress_forwarding_flow_entry(dpid)
    add_default_classifier_forwarding_flow_entry(dpid)
    add_default_arp_forwarding_flow_entry(dpid, Configuration::INTERFACES)
    add_default_routing_forwarding_flow_entry(dpid, Configuration::INTERFACES)

    add_default_arp_lookup_flooding_flow_entry(dpid)
    add_default_egress_forwarding_flow_entry(dpid)
  end

  def packet_in(dpid, message)
    return unless sent_to_router?(message)
    case message.data
    when Arp::Request
      packet_in_arp_request dpid, message.in_port, message.data
      add_arp_reply_flow_entry dpid, message.in_port, message.data
    when Arp::Reply
      packet_in_arp_reply dpid, message
    when Parser::IPv4Packet
      #packet_in_ipv4 dpid, message
      add_routing_table_entry(dpid, message)
    else
      logger.debug "Dropping unsupported packet type: #{message.data.inspect}"
    end
  end

  def packet_in_arp_request(dpid, in_port, arp_request)
logger.info "packet_in_arp_request"
    interface =
      @interfaces.find_by(port_number: in_port,
                          ip_address: arp_request.target_protocol_address)
    return unless interface

   send_packet_out(
      dpid,
      raw_data: Arp::Reply.new(
        destination_mac: arp_request.source_mac,
        source_mac: interface.mac_address,
        sender_protocol_address: arp_request.target_protocol_address,
        target_protocol_address: arp_request.sender_protocol_address
     ).to_binary,
     actions: SendOutPort.new(in_port))

   
   end

  def packet_in_arp_reply(dpid, message)
logger.info "packet_in_arp_reply"
    @arp_table.update(message.in_port,
                      message.sender_protocol_address,
                      message.source_mac)

    flush_unsent_packets(dpid,
                         message.data,
                         @interfaces.find_by(port_number: message.in_port))
  end

  def packet_in_ipv4(dpid, message)
    if forward?(message)
      forward(dpid, message)
    elsif message.ip_protocol == 1
      icmp = Icmp.read(message.raw_data)
      packet_in_icmpv4_echo_request(dpid, message) if icmp.icmp_type == 8
    else
      logger.debug "Dropping unsupported IPv4 packet: #{message.data}"
    end
  end

  def packet_in_icmpv4_echo_request(dpid, message)
    icmp_request = Icmp.read(message.raw_data)
    if @arp_table.lookup(message.source_ip_address)
      send_packet_out(dpid,
                      raw_data: create_icmp_reply(icmp_request).to_binary,
                      actions: SendOutPort.new(message.in_port))
    else
      send_later(dpid,
                 interface: @interfaces.find_by(port_number: message.in_port),
                 destination_ip: message.source_ip_address,
                 data: create_icmp_reply(icmp_request))
    end
  end

  private

  def sent_to_router?(message)
    return true if message.destination_mac.broadcast?
    interface = @interfaces.find_by(port_number: message.in_port)
    interface && interface.mac_address == message.destination_mac
  end

  def forward?(message)
    !@interfaces.find_by(ip_address: message.destination_ip_address)
  end

  def forward(dpid, message)
logger.info "forwarding"
    next_hop = resolve_next_hop(message.destination_ip_address)

    interface = @interfaces.find_by_prefix(next_hop)
    return if !interface || (interface.port_number == message.in_port)
logger.info "found interface"

    arp_entry = @arp_table.lookup(next_hop)

    if arp_entry
logger.info "found next hop"
       actions = [SetSourceMacAddress.new(interface.mac_address),
                  SetDestinationMacAddress.new(arp_entry.mac_address),
                  SendOutPort.new(interface.port_number)]
      send_flow_mod_add(dpid, table_id: arp_lookup_TABLE_ID, match: ExactMatch.new(message), instructions: Apply.new(actions))
      send_packet_out(dpid, raw_data: message.raw_data, actions: actions)
    else
      send_later(dpid,
                 interface: interface,
                 destination_ip: next_hop,
                 data: message.data)
    end
  end

  def resolve_next_hop(destination_ip_address)
    interface = @interfaces.find_by_prefix(destination_ip_address)
    if interface
      destination_ip_address
    else
      @routing_table.lookup(destination_ip_address)
    end
  end

  def create_icmp_reply(icmp_request)
    Icmp::Reply.new(identifier: icmp_request.icmp_identifier,
                    source_mac: icmp_request.destination_mac,
                    destination_mac: icmp_request.source_mac,
                    destination_ip_address: icmp_request.source_ip_address,
                    source_ip_address: icmp_request.destination_ip_address,
                    sequence_number: icmp_request.icmp_sequence_number,
                    echo_data: icmp_request.echo_data)
  end

  def send_later(dpid, options)
logger.info "send later"
    destination_ip = options.fetch(:destination_ip)
    @unresolved_packet_queue[destination_ip] += [options.fetch(:data)]
    send_arp_request(dpid, destination_ip, options.fetch(:interface))
  end

  def flush_unsent_packets(dpid, arp_reply, interface)
    destination_ip = arp_reply.sender_protocol_address
    @unresolved_packet_queue[destination_ip].each do |each|
      rewrite_mac =
        [SetDestinationMacAddress.new(arp_reply.sender_hardware_address),
         SetSourceMacAddress.new(interface.mac_address),
         SendOutPort.new(interface.port_number)]
      send_packet_out(dpid, raw_data: each.to_binary_s, actions: rewrite_mac)
    end
    @unresolved_packet_queue[destination_ip] = []
  end

  def send_arp_request(dpid, destination_ip, interface)
logger.info "send request"
    arp_request =
      Arp::Request.new(source_mac: interface.mac_address,
                       sender_protocol_address: interface.ip_address,
                       target_protocol_address: destination_ip)
    send_packet_out(dpid,
                    raw_data: arp_request.to_binary,
                    actions: SendOutPort.new(interface.port_number))
  end

  def add_routing_table_entry(dpid, message)
    send_flow_mod_add(
      dpid,
      table_id: ROUTING_TABLE_ID,
      idle_timeout: AGING_TIME,
      priority: 10,
      match: Match.new(dl_type: 0x0800,
                       nw_dst: "192.168.1.0/255.255.255.0"),
      instructions: [Apply.new(NiciraRegMove.new(from: message.nw_dst,
						 to: :reg0)),
                    GotoTable.new(LOAD_ARP_TABLE_ID)]
    )
    send_flow_mod_add(
      dpid,
      table_id: ROUTING_TABLE_ID,
      idle_timeout: AGING_TIME,
      priority: 10,
      match: Match.new(dl_type: 0x0800,
                       nw_dst: "192.168.2.0/255.255.255.0"),
      instructions: [Apply.new(NiciraRegMove.new(from: message.nw_dst,
						 to: :reg0)),
                    GotoTable.new(LOAD_ARP_TABLE_ID)]
    )
    send_flow_mod_add(
      dpid,
      table_id: ROUTING_TABLE_ID,
      idle_timeout: 0,
      priority: 0,
      match: Match.new,
      instructions: [Apply.new(NiciraRegLoad.new("0xc0a80102", :reg0)),
                     GotoTable.new(LOAD_ARP_TABLE_ID)]
    )
  end

  def add_default_ingress_forwarding_flow_entry(dpid)
    send_flow_mod_add(
      dpid,
      table_id: INGRESS_TABLE_ID,
      idle_timeout: 0,
      match: Match.new,
      instructions: GotoTable.new(CLASSIFIER_TABLE_ID)
    )
  end 

  def add_default_classifier_forwarding_flow_entry(dpid)

# Send ARP to ARP Responder
    send_flow_mod_add(
      dpid,
      table_id: CLASSIFIER_TABLE_ID,
      idle_timeout: 0,
      match: Match.new(ether_type: 0x0806),
      instructions: GotoTable.new(ARP_RESPONDER_TABLE_ID)
    )
# Send L3 traffic to L3 Rewrite Table
    send_flow_mod_add(
      dpid,
      table_id: CLASSIFIER_TABLE_ID,
      idle_timeout: 0,
      match: Match.new(ether_type: 0x0800),
      instructions: GotoTable.new(ROUTING_TABLE_ID)
    )
  end

def add_default_arp_forwarding_flow_entry(dpid, interfaces)
    interfaces.map do |each|
    arp_reply_actions = [
                SendOutPort.new(:controller),
		NiciraRegMove.new(from: :source_mac_address,to: :destination_mac_address),
		SetSourceMacAddress.new(each.fetch(:mac_address)),
                SetArpOperation.new(Arp::Reply::OPERATION),
                NiciraRegMove.new(from: :arp_sender_protocol_address,to: :arp_target_protocol_address),
                NiciraRegMove.new(from: :arp_sender_hardware_address,to: :arp_target_hardware_address), 
                SetArpSenderHardwareAddress.new(each.fetch(:mac_address)),
                SetArpSenderProtocolAddress.new(each.fetch(:ip_address)),
                NiciraRegLoad.new(each.fetch(:port), :reg1),
                NiciraRegLoad.new(0xffff, :in_port)
    ]
    arp_default_actions = [
        SetSourceMacAddress.new(each.fetch(:mac_address)),
        SetArpSenderHardwareAddress.new(each.fetch(:mac_address)),
        SetArpSenderProtocolAddress.new(each.fetch(:ip_address))
    ]
 #send flow mod for arp request
 send_flow_mod_add(
       dpid, 
       table_id: ARP_RESPONDER_TABLE_ID, 
       match: Match.new(ether_type: 0x0806, 
                        arp_operation: Arp::Request::OPERATION, 
                        arp_target_protocol_address: each.fetch(:ip_address),
                        in_port: each.fetch(:port)), 
       instructions: [Apply.new(arp_reply_actions), GotoTable.new(EGRESS_TABLE_ID)])

 #send flow mod for arp reply
    send_flow_mod_add(
       dpid, 
       table_id: ARP_RESPONDER_TABLE_ID, 
       match: Match.new(ether_type: 0x0806, 
                        arp_operation: Arp::Reply::OPERATION, 
                        arp_target_protocol_address: each.fetch(:ip_address),
                        in_port: each.fetch(:port)), 
       instructions: Apply.new(SendOutPort.new(:controller)))
 #set the rest 
     send_flow_mod_add(
       dpid, 
       table_id: ARP_RESPONDER_TABLE_ID, 
       match: Match.new(ether_type: 0x0806, 
                        reg1: each.fetch(:port)), 
       instructions: [Apply.new(arp_default_actions), GotoTable.new(EGRESS_TABLE_ID)])   
    end
end

 def add_default_routing_forwarding_flow_entry(dpid, interfaces)
    default_mask = IPv4Address.new('255.255.255.255')
    interfaces.map do |each|
     
     nw_address = IPv4Address.new(each.fetch(:ip_address))
     netmask_length = each.fetch(:netmask_length)
     mask_address = nw_address.mask(netmask_length)
     default_mask_address = default_mask.mask(netmask_length)
     send_flow_mod_add(
       dpid,
       table_id: ROUTING_TABLE_ID,
       priority: 40024,
       match: Match.new(ether_type: 0x0800, 
                        ipv4_destination_address: mask_address,
                        ipv4_destination_address_mask: default_mask_address),
       instructions: [Apply.new(NiciraRegMove.new(from: :ipv4_destination_address,to: :reg0)), GotoTable.new(INTERFACE_LOOKUP_TABLE_ID)])
    end
    nw_address = IPv4Address.new('192.168.1.2')
    send_flow_mod_add(
      dpid,
      table_id: ROUTING_TABLE_ID,
      priority: 0,
      match: Match.new(ether_type: 0x0800),
      instructions: [Apply.new(NiciraRegLoad.new(nw_address.to_i, :reg0)),
                     GotoTable.new(INTERFACE_LOOKUP_TABLE_ID)]
    )
 end 
 
 def add_default_arp_lookup_flooding_flow_entry(dpid)
    send_flow_mod_add(
      dpid,
      table_id: ARP_LOOKUP_TABLE_ID,
      idle_timeout: 0,
      priority: 1,
      match: Match.new(ether_type: 0x0800),
      instructions: Apply.new(SendOutPort.new(:controller))
    )
 end

def add_arp_reply_flow_entry(dpid, in_port, arp_request)
    interface =
      @interfaces.find_by(port_number: in_port,
                          ip_address: arp_request.target_protocol_address)
    return unless interface
logger.info "add arp_reply flow"

      actions = [
                SendOutPort.new(:controller),
		NiciraRegMove.new(from: :source_mac_address,to: :destination_mac_address),
		SetSourceMacAddress.new(interface.mac_address),
                SetArpOperation.new(Arp::Reply::OPERATION),
                NiciraRegMove.new(from: :arp_sender_protocol_address,to: :arp_target_protocol_address),
                NiciraRegMove.new(from: :arp_sender_hardware_address,to: :arp_target_hardware_address), 
                SetArpSenderHardwareAddress.new(interface.mac_address),
                SetArpSenderProtocolAddress.new(interface.ip_address),
                NiciraRegLoad.new(in_port, :reg1)
               ]
      send_flow_mod_add(dpid, table_id: ARP_RESPONDER_TABLE_ID, idle_timeout: 0,
      priority: 2, match: Match.new(ether_type: 0x0806, arp_operation: Arp::Request::OPERATION, arp_target_protocol_address: arp_request.target_protocol_address), instructions: [Apply.new(actions), GotoTable.new(EGRESS_TABLE_ID)])

end 

def add_default_egress_forwarding_flow_entry(dpid)
  send_flow_mod_add(dpid, table_id: EGRESS_TABLE_ID, match: Match.new, instructions: Apply.new(NiciraSendOutPort.new(:reg1)))
end
end
