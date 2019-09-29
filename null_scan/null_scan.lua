-- needs to be outside function called from menu
-- grabs the tcp.stream, tcp flags, srcport and dstport fields
local tcp_stream_info = Field.new("tcp.stream");
local tcp_flags_field = Field.new("tcp.flags")
local tcp_srcport_field = Field.new("tcp.srcport")
local tcp_dstport_field = Field.new("tcp.dstport")

-- Scans to test against - Individual TCP stream length vary from 1 to 2 in each of these scans
-- Null scan (-sN) - <None> - returns flag value of 0/0x000 
-- FIN scan (-sF) - FIN - returns flag value of 1/0x01
-- Xmas scan (-sX) - FIN-PSH-URG - returns flag value of 41/0x029 

-- TCP FLAGS
local tcp_flags = { [0] = "NONE", [1] = "FIN", [2] = "SYN", [4] = "RST", [8] = "PSH", [16] = "ACK", [17] = "FIN-ACK", [18] = "SYN-ACK",
[20] = "RST-ACK", [24] = "PSH-ACK", [25] = "FIN-PSH-ACK", [32] = "URG", [41] = "FIN-PSH-URG"}

-- method will be called from menu context Tools-->Null-tools-->Port-Scans
function port_scans()

    local tw = TextWindow.new("Possible Port Scans");
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
        tcp_stream_index = tcp_stream_info();
        -- null/nil check
        if (tcp_stream_index ~= nil) then

            -- extract source, destination IP from packets
            local src = tostring(pinfo.src) or 0
            local dst = tostring(pinfo.dst) or 0

            local flags = tcp_flags_field()
            if flags then
                local set_tcp_flags = flags.value

                if (flags.value ~= nil) then
                    set_tcp_flags = tcp_flags[flags.value]
                end

                packet = {TCP_INDEX=tonumber(tostring(tcp_stream_index)), FRAME_NO=pinfo.number, FLAGS=set_tcp_flags, srcPort=tostring(tcp_srcport_field()), dstPort=tostring(tcp_dstport_field())}
                streams_unsorted[iterator] = packet
                
                -- lua arrays start on 1
                iterator = iterator + 1
            end
            
        end	
        
        -- this function will be called once every few seconds to update the window
		function tap.draw(t)
            tw:clear()

            -- find highest TCP index
            local tcp_index_max = 0
            for i, item in pairs(streams_unsorted) do
                -- i is iterator and item is packet_item

                if (item.TCP_INDEX > tcp_index_max) then
                    tcp_index_max = item.TCP_INDEX
                end
                
            end
            
            -- fills a 2D array with sorted streams and appends them to the text window
            for i=0, tcp_index_max do  
                nested_iterator = 1
                streams_sorted[i] = {}        

                for j, item in pairs(streams_unsorted) do

                    if (i == item.TCP_INDEX) then
                        streams_sorted[i][nested_iterator] = item
                        nested_iterator = nested_iterator + 1
                    end
                end
            end

            -- #streams_sorted/#streams_sorted[1] returns length of the array
            --  runs through the sorted streams and prints them out
            for i=0, #streams_sorted do
                if (#streams_sorted[i] <= 2) then
                    possible_scan = ''
                    -- arrays start on 1 
                    if (streams_sorted[i][1].FLAGS == "FIN-PSH-URG") then
                        possible_scan = 'Xmas Scan'
                    end
                    if (streams_sorted[i][1].FLAGS == "FIN") then
                        possible_scan = 'FIN Scan'
                    end
                    if (streams_sorted[i][1].FLAGS == "NONE") then
                        possible_scan = 'Null Scan'
                    end

                    tw:append('Possible Scan: ' .. possible_scan .." TCP Stream Index: " .. i .. " Length: " .. #streams_sorted[i] .. "\r\n\r\n")
                    
                    for j, item in pairs(streams_sorted[i]) do
                        tw:append("\t" .. " Frame No: " .. item.FRAME_NO .. " SRC/DST: " .. item.srcPort .. " => " .. item.dstPort .. " Flags: " .. item.FLAGS .. '\r\n')
                    end
                    tw:append('\r\n')
                end
            end


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

-- method will be called from menu context Tools-->Null-tools-->SQL-Injections
function sql_injections()

    local tw = TextWindow.new("Possible SQL Injections");
    local tap = Listener.new('tcp');

    local function remove()
		-- removes the listener as to not run indefinitely
		tap:remove();
    end
    
    --  call remove() function when closing window
    tw:set_atclose(remove)
    
    -- will be run on every packet 
    -- last_index = 0

    function tap.packet(pinfo,tvb)

            -- extract source, destination IP from packets
            -- local src = tostring(pinfo.src) or 0
            -- local dst = tostring(pinfo.dst) or 0

            -- LUA string pattern functions
            -- string.match("examples", 'examples')
            -- string.find('example', 'ex')
        
        -- this function will be called once every few seconds to update the window
		function tap.draw(t)
            tw:clear()
            tw:append('Placeholder')
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


-- assigns function and menu option as Tools-->Null-tools-->Port-Scans
register_menu("Null-Tools/Port-Scans", port_scans, MENU_TOOLS_UNSORTED)
register_menu("Null-Tools/SQL-Injections", sql_injections, MENU_TOOLS_UNSORTED)
