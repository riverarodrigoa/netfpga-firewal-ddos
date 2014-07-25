///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: header_e 2014-07 $
//
// Module: header_e.v
// Project: Firewall DDoS
// Description: Modulo encargado de la extraccion de la cabecera
//              de los paquetes y filtro de paquetes TCP
///////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps


//`define UDP_REG_ADDR_WIDTH 2
//`define CPCI_NF2_DATA_WIDTH 32

module header_e
   #(
      parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8,
      parameter UDP_REG_SRC_WIDTH = 2
   )
   (
      input  [DATA_WIDTH-1:0]             in_data,
      input  [CTRL_WIDTH-1:0]             in_ctrl,
      input                               in_wr,
      output                              in_rdy,

    //Interface con firewall
      output [31:0]			  dst_ip,
      output [31:0]			  src_ip,
      output [15:0]			  src_port,
      output [15:0]			  dst_port,
      output  [7:0]			  proto,
      

      // --- Register interface
      input                               reg_req_in,
      input                               reg_ack_in,
      input                               reg_rd_wr_L_in,
      input  [`UDP_REG_ADDR_WIDTH-1:0]    reg_addr_in,
      input  [`CPCI_NF2_DATA_WIDTH-1:0]   reg_data_in,
      input  [UDP_REG_SRC_WIDTH-1:0]      reg_src_in,

      output                              reg_req_out,
      output                              reg_ack_out,
      output                              reg_rd_wr_L_out,
      output  [`UDP_REG_ADDR_WIDTH-1:0]   reg_addr_out,
      output  [`CPCI_NF2_DATA_WIDTH-1:0]  reg_data_out,
      output  [UDP_REG_SRC_WIDTH-1:0]     reg_src_out,

      // misc
      input                                reset,
      input                                clk
   );


   //------------------------- Signals-------------------------------
   localparam SKIPTONEXTPACKET = 0;
   localparam EXTRACTFIELDS    = 1;
   localparam WROUT	       = 2;
/*
   localparam WRITEFIELD0      = 2;
   localparam WRITEFIELD1      = 3;
   localparam WRITEFIELD2      = 4;
*/
   wire [DATA_WIDTH-1:0]       in_fifo_data;
   wire [CTRL_WIDTH-1:0]       in_fifo_ctrl;
   wire                        in_fifo_nearly_full;
   wire                        in_fifo_empty;
   reg                         in_fifo_rd_en;

   reg [31:0] ipsrc, ipdst;
   reg [3:0]  ipversion;
   reg        swap_tuple;

   reg [15:0] tcp_src_port, tcp_dst_port;

   reg [7:0]  protocol_field;
   reg [1:0]  protocol_ident;

// reg [15:0] packet_len_field;   

// reg [7:0]  tos;
// reg [7:0]  ttl;   
// reg [7:0]  tcpflags;
   
// reg [15:0] doctets;           
   reg [15:0] input_port; 

   wire       l3proto_ok;
   reg        l4proto_ok;

   reg [3:0]  cnt;
   reg        cnt_reset;

   reg [2:0]  fsm_state, nfsm_state;

   wire       in_fifo_data_rdy;
   reg        registers_ready;
   reg        allow_extract;
   reg        accepted;
   reg [31:0] cnt_accepted;
   reg [31:0] cnt_discarded;
   reg        total_en;
   reg [31:0] cnt_total;
   wire [63:0] reg_sw;


   //------------------------- Modules-------------------------------
   
   fallthrough_small_fifo #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(2)
   ) input_fifo (
      .din           ({in_ctrl, in_data}),   // Data in
      .wr_en         (in_wr),                // Write enable
      .rd_en         (in_fifo_rd_en),        // Read the next word 
      .dout          ({in_fifo_ctrl, in_fifo_data}),
      .full          (),
      .nearly_full   (in_fifo_nearly_full),
      .empty         (in_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );   

    generic_regs
   #( 
      .UDP_REG_SRC_WIDTH   (UDP_REG_SRC_WIDTH),
      .TAG                 (`FW_HEADER_E_BLOCK_TAG),  
      .REG_ADDR_WIDTH      (`FW_HEADER_E_REG_ADDR_WIDTH), // Width of block addresses -- eg. MODULE_REG_ADDR_WIDTH
      .NUM_COUNTERS        (0),                 // Number of counters
      .NUM_SOFTWARE_REGS   (2),                 // Number of sw regs
      .NUM_HARDWARE_REGS   (3)                  // Number of hw regs
   ) module_regs (
      .reg_req_in       (reg_req_in),
      .reg_ack_in       (reg_ack_in),
      .reg_rd_wr_L_in   (reg_rd_wr_L_in),
      .reg_addr_in      (reg_addr_in),
      .reg_data_in      (reg_data_in),
      .reg_src_in       (reg_src_in),

      .reg_req_out      (reg_req_out),
      .reg_ack_out      (reg_ack_out),
      .reg_rd_wr_L_out  (reg_rd_wr_L_out),
      .reg_addr_out     (reg_addr_out),
      .reg_data_out     (reg_data_out),
      .reg_src_out      (reg_src_out),

      // --- counters interface
      .counter_updates  (),
      .counter_decrement(),

      // --- SW regs interface *****REVISAR****
      //.software_regs    (reg_sw),

      // --- HW regs interface
      //.hardware_regs    ({cnt_discarded, cnt_accepted, cnt_total}),

      .clk              (clk),
      .reset            (reset)
    );



   //------------------------- Local assignments -------------------------------

   assign in_rdy           = !in_fifo_nearly_full;
   //assign in_rdy           = !in_fifo_nearly_full && reg_sw[0];
   assign in_fifo_data_rdy = !in_fifo_empty;

   //------------------------- Logic-------------------------------

   always @(posedge clk) begin
      if (allow_extract && in_fifo_data_rdy) begin
         case (cnt)
            0: begin
                  input_port      = in_fifo_data[31:16];    
               end

            2: begin
                  packet_len_field = in_fifo_data[31:16];
                  ipversion        = in_fifo_data[15:12]; 
               // tos              = in_fifo_data[7:0];
               end

            3: begin
               // doctets         = in_fifo_data[63:48];
               // ttl             = in_fifo_data[15:8];
                  protocol_field  = in_fifo_data[7:0];
               end

            4: begin
                  ipsrc           = in_fifo_data[47:16];
                  ipdst[31:16]    = in_fifo_data[15:0]; 
               end   

            5: begin
                  ipdst[15:0]     = in_fifo_data[63:48];
                  tcp_src_port    = in_fifo_data[47:32];
                  tcp_dst_port    = in_fifo_data[31:16];
               end

           default:   ;     
         endcase    
      end
   end

   always @(posedge clk) begin
      swap_tuple = (ipsrc > ipdst);
   end

   always @(posedge clk) begin
      if (cnt_reset || reset)
         cnt <= 0;
      else begin
         if (allow_extract && in_fifo_data_rdy) begin
            cnt <= cnt + 1;
         end    
      end
   end

   always @(*) begin
      allow_extract  = 0;
      in_fifo_rd_en  = 0;
      cnt_reset      = 0;
      out_wr         = 0;
      out_ctrl       = 'h0;
      out_data       = {ipsrc, ipdst};
      nfsm_state     = fsm_state;    
      accepted       = 0;
      total_en       = 0;
      case (fsm_state)
         SKIPTONEXTPACKET: begin
            cnt_reset  = 1;
            if (in_fifo_data_rdy) begin
               if (in_fifo_ctrl == 'hff)
                  nfsm_state = EXTRACTFIELDS;
               else
                  in_fifo_rd_en  = 1;
            end
         end

         EXTRACTFIELDS: begin 
            if (in_fifo_data_rdy) begin
               allow_extract = 1;
               in_fifo_rd_en = 1;
               if (cnt == 5) begin
                  total_en      = 1;
                  if (l3proto_ok && l4proto_ok)      
                     nfsm_state = WROUT;
                  else
                     nfsm_state = SKIPTONEXTPACKET;
               end
            end
         end
	
	WROUT: begin
	  dst_ip = ipdst;
	  src_ip = ipsrc;
	  src_port = tcp_src_port;
	  dst_port = tcp_dst_port;
	  proto = protocol_field;
	  if (out_rdy) begin
               out_wr   = 1;
               nfsm_state = SKIPTONEXTPACKET;
            end
         end
/*
         WRITEFIELD0: begin
            out_data = {(protocol_ident == 2)?
                          ((swap_tuple && reg_sw[32])? {tcp_dst_port, tcp_src_port} : {tcp_src_port, tcp_dst_port}) :
                           32'b0, {8{~reg_sw[32]}} & input_port[7:0], protocol_field, 8'b0};
            if (out_rdy) begin
               out_wr   = 1;
               nfsm_state = WRITEFIELD1;
            end
         end

         WRITEFIELD1: begin
            out_data = (swap_tuple && reg_sw[32])? {ipdst, ipsrc} : {ipsrc, ipdst};
            if (out_rdy) begin
               out_wr   = 1;
               nfsm_state = SKIPTONEXTPACKET;
            end
         end
*/
      endcase                    
   end

   always @(posedge clk) begin
      if (reset)
         fsm_state = SKIPTONEXTPACKET;
      else
         fsm_state = nfsm_state;
   end

   // Proceso solo de IPv4         
   assign l3proto_ok = (packet_len_field == 16'h0800)? 1:0;    

   //Verificacion del protocolo
   always @(*) begin
      l4proto_ok     = 1;
      protocol_ident = 0;

      case (protocol_field)
     //  1: protocol_ident = 1; //ICMP
         6: protocol_ident = 2; //TCP
     // 17: protocol_ident = 3; //UDP
        default: l4proto_ok = 0;
      endcase
   end
/*
   always @(posedge clk) begin
      if (reset)
         cnt_accepted = 'h0;
      else
         if (accepted)
         cnt_accepted = cnt_accepted + 1;
   end
   
   always @(posedge clk) begin
     cnt_discarded = cnt_total - cnt_accepted;
   end

   always @(posedge clk) begin
      if (reset)
         cnt_total = 'h0;
      else
         if (total_en)
         cnt_total = cnt_total + 1;
   end
*/           
endmodule
