module challenge(input clk, input cs, input i, output o);
    localparam MAGIC = 32'h1337beef;
    localparam FLAG  = 256'h666c61677b465047413a204a75737420616c6f74204c555420616e642046467d;

    reg [31:0] shift = 0;
    reg [255:0] flag = 0;
    
    reg magic = 0;
    assign o = magic ? flag[0] : shift[0];

    always @(posedge clk) begin
        if(!cs) begin
            shift <= {i, shift[31:1]};
            flag <= {i, flag[255:1]};
        end else begin
            if(shift == MAGIC) magic <= 1;
            shift <= 0;
            flag <= FLAG;
        end
    end
endmodule
