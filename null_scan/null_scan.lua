-- needs to be outside function called from menu
-- grabs the tcp.stream and tcp flags fields
local tcp_stream_info = Field.new("tcp.stream");
local tcp_flags = Field.new("tcp.flags")

-- TCP FLAGS
local tcp_fin = 1 -- 0x01
local tcp_syn = 2 -- 0x02
local tcp_rst = 4 -- 0x04
local tcp_ack = 16 -- 0x10
local tcp_syn_ack = 18 -- 0x12

function tcp_stream()

    local tw = TextWindow.new("TCP Stream Index");
    local tap = Listener.new('tcp');
    local streams_unsorted = {}
    local streams_sorted = { }
    local iterator = 1
    local function remove()
		-- removes the listener as to not run indefinitely
		tap:remove();
    end
    
    --  call remove() function when closing window
    tw:set_atclose(remove)
    
    -- tw:append('Debug: before tap.packet');

    -- will be run on every packet 
    -- last_index = 0

    function tap.packet(pinfo,tvb)
        local tcp_stream_index = tcp_stream_info();
        -- null check, lua... "nil"
        if tcp_stream_index ~= nil then

            -- extract source, destination IP from packets
            local src = tostring(pinfo.src) or 0
            local dst = tostring(pinfo.dst)or 0
            -- extract tcp flags in hex
            local flags = tcp_flags()
            if flags then
                local flags_formatted = string.format("tcp.flags = %#x", flags.value)
                -- "Frame no: " .. pinfo.number
                local packet_item = "TCP Index: " .. tostring(tcp_stream_index) .. " Frame No: " .. pinfo.number 
                local tcp_flag=""
                if (flags.value == tcp_fin) then
                    tcp_flag = "FIN"
                end
                if (flags.value == tcp_syn) then
                    tcp_flag = "SYN"
                end
                if (flags.value == tcp_ack) then
                    tcp_flag = "ACK"
                end
                if (flags.value == tcp_syn_ack) then
                    tcp_flag = "SYN-ACK"
                end
                if (flags.value == tcp_rst) then
                    -- tw:append("Flag: RST flag\r\n")
                    tcp_flag = "RST"
                end

                -- lua arrays start on 1
                packet_item = packet_item .. " Flag: " .. tcp_flag .. "\r\n"
                streams_unsorted[iterator] = packet_item
                iterator = iterator + 1
                -- tw:append(packet_item)

                -- tw:append("Frame no: " .. pinfo.number .. " Index: " .. tostring(tcp_stream_index) .. " src: " .. src .. " dst: " .. dst .. " flags: " .. tcp_flag .. "\r\n");
            end
            
        end	
        
        -- this function will be called once every few seconds to update the window
		function tap.draw(t)
            tw:clear()

            -- find highest TCP index
            local tcp_index_max = 0
            for i, item in pairs(streams_unsorted) do
                -- i is iterator and item is packet_item
                index_num = string.match(item, "%d+")
                index_num = tonumber(index_num)
                if (index_num > tcp_index_max) then
                    tcp_index_max = index_num
                end
                -- tw:append("Got from string" .. index_num .. " :s: ")
                -- tw:append(item);
                
            end
            
            -- fills a 2D array with sorted streams and appends them to the text window
            for i=0, tcp_index_max do  
                tw:append("TCP Stream Index: " .. i .. "\r\n")
                nested_iterator = 1
                streams_sorted[i] = {}          
                for j, item in pairs(streams_unsorted) do
                    index_num = string.match(item, "%d+")
                    index_num = tonumber(index_num)
                    if (i == index_num) then
                        streams_sorted[i][nested_iterator] = item
                        nested_iterator = nested_iterator + 1
                        tw:append("\t" .. item)
                    end
                end 
            end

		end
    end
    
    -- tw:append('Debug: after tap.packet');

    -- this function will be called whenever a reset is needed
	-- for instance when reloading the capture file
    function tap.reset()
		tw:clear()
	end

    -- ensure that all existing packets are processed.
    retap_packets()
end

-- assigns function and menu option as Tools-->Null-tools-->TCP-Stream
register_menu("Null-Scan/TCP-Stream", tcp_stream, MENU_TOOLS_UNSORTED)
