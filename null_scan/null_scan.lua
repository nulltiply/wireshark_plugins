-- needs to be outside function called from menu
-- grabs the tcp.stream and tcp flags fields
local tcp_stream_info = Field.new("tcp.stream");
local tcp_flags_field = Field.new("tcp.flags")

-- Scans to test against
-- Null scan (-sN) - <None> - returns flag value of 0/0x000 
-- FIN scan (-sF) - FIN - returns flag value of 1/0x01
-- Xmas scan (-sX) - FIN-PSH-URG - returns flag value of 41/0x029 

-- TCP FLAGS
local tcp_flags = { [0] = "NONE", [1] = "FIN", [2] = "SYN", [4] = "RST", [8] = "PSH", [16] = "ACK", [17] = "FIN-ACK", [18] = "SYN-ACK",
[20] = "RST-ACK", [24] = "PSH-ACK", [25] = "FIN-PSH-ACK", [32] = "URG", [41] = "FIN-PSH-URG"}

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
    
    -- will be run on every packet 
    -- last_index = 0

    function tap.packet(pinfo,tvb)
        local tcp_stream_index = tcp_stream_info();
        -- null/nil check
        if (tcp_stream_index ~= nil) then

            -- extract source, destination IP from packets
            local src = tostring(pinfo.src) or 0
            local dst = tostring(pinfo.dst)or 0
            -- extract tcp flags in hex
            local flags = tcp_flags_field()
            if flags then
                local flags_formatted = string.format("tcp.flags = %#x", flags.value)
                local packet_item = "TCP Index: " .. tostring(tcp_stream_index) .. " Frame No: " .. pinfo.number 
                local set_tcp_flags = flags.value

                if (flags.value ~= nil) then
                    set_tcp_flags = tcp_flags[flags.value]
                end
                -- lua arrays start on 1
                packet_item = packet_item .. " Flag: " .. set_tcp_flags .. "\r\n"
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
                
            end
            
            -- fills a 2D array with sorted streams and appends them to the text window
            for i=0, tcp_index_max do  
                tw:append("TCP Stream Index: " .. i .. "\r\n")
                nested_iterator = 1
                streams_sorted[i] = {}        

                tcp_stream_length = 0
                for j, item in pairs(streams_unsorted) do
                    index_num = string.match(item, "%d+")
                    index_num = tonumber(index_num)
                    
                    if (i == index_num) then
                        streams_sorted[i][nested_iterator] = item
                        nested_iterator = nested_iterator + 1
                        tw:append("\t" .. item)
                        tcp_stream_length = tcp_stream_length + 1
                    end
                end
                tw:append("TCP Stream Length: " .. tcp_stream_length .. "\r\n") 
            end
            -- last iteration to check for possible scans?
            -- get length here instead table.getn(array) 

		end
    end
    
    -- this function will be called whenever a reset is needed
	-- for instance when reloading the capture file
    function tap.reset()
		tw:clear()
	end

    -- ensure that all existing packets are processed.
    retap_packets()
end

-- assigns function and menu option as Tools-->Null-tools-->TCP-Stream
register_menu("Null-Tools/TCP-Stream", tcp_stream, MENU_TOOLS_UNSORTED)
