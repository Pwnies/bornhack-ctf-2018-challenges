module challenge_tb();
    reg clk = 0;
    reg cs = 1;
    reg i = 0;
    wire o;

    reg [31:0] magic = 32'h1337beef;
    reg [255:0] flag;
    integer j;
    
    challenge chal0 (.clk(clk), .cs(cs), .i(i), .o(o));

    initial begin
        $dumpfile("challenge.vcd");
        $dumpvars(0, challenge_tb);
        
        cs = 0;
        for(j = 0; j < 32; j = j + 1) begin
            i = magic[0];
            #1 clk = !clk;
            #1 clk = !clk;
            magic = {1'b0, magic[31:1]};
        end

        cs = 1;
        #1 clk = !clk;
        #1 clk = !clk;
        cs = 0;

        for(j = 0; j < 256; j = j + 1) begin
            flag = {o, flag[255:1]};
            #1 clk = !clk;
            #1 clk = !clk;
        end

        $display("flag = %x", flag);

        $finish();
    end
endmodule
