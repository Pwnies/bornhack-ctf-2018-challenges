module tb (/*AUTOARG*/ ) ;
   reg   sclk;
   reg   ss;
   reg   mosi;
   wire  miso;
   integer i;

   chip dut(ss, sclk, mosi, miso);

   initial begin
      $monitor(sclk,miso);
      // $dumpfile("test.vcd");
      // $dumpvars(tb);

      ss <= 1;

      #1 sclk <= 0;
      #1 sclk <= 1;
      #1 sclk <= 0;

      ss <= 0;
      mosi <= 0;
      #8;

      for(i = 0; i < 256; i = i + 1) begin
         #1 sclk = !sclk;
         #1 sclk = !sclk;
      end
   end



endmodule // tb
